#!/usr/bin/env python3
"""Создаёт совсем маленький образец из полного образца.

Для каждого верхнеуровневого тега выбирается объект с самым большим
поддеревом (то есть наиболее полный по вложенности вариант).
"""

from __future__ import annotations

import copy
from collections import Counter
from pathlib import Path

from lxml import etree


def main() -> None:
    source = Path("data/input_sample.xml")
    target = Path("data/mini_input.xml")

    nsmap: dict[str | None, str] = {}
    root_tag = None
    root_attrib: dict[str, str] = {}
    root_elem = None

    best: dict[str, tuple[int, object]] = {}
    counts: Counter[str] = Counter()

    for event, payload in etree.iterparse(
        str(source), events=("start-ns", "start", "end"), huge_tree=True
    ):
        if event == "start-ns":
            prefix, uri = payload
            nsmap.setdefault(prefix, uri)
        elif event == "start":
            elem = payload
            if root_tag is None:
                root_tag = elem.tag
                root_attrib = dict(elem.attrib)
                root_elem = elem
        else:
            elem = payload
            parent = elem.getparent()
            if parent is not None and parent is root_elem:
                counts[elem.tag] += 1
                size = sum(1 for _ in elem.iter())
                current = best.get(elem.tag)
                if current is None or size > current[0]:
                    best[elem.tag] = (size, copy.deepcopy(elem))

                elem.clear()
                while elem.getprevious() is not None:
                    del parent[0]

    target.parent.mkdir(parents=True, exist_ok=True)
    out_file = target.open("wb")
    xml_cm = etree.xmlfile(out_file, encoding="utf-8")
    xml_file = xml_cm.__enter__()
    xml_file.write_declaration()
    try:
        root_ctx = xml_file.element(root_tag, attrib=root_attrib, nsmap=nsmap)
        root_ctx.__enter__()
        try:
            for tag in sorted(best, key=lambda t: t):
                xml_file.write(best[tag][1])
        finally:
            root_ctx.__exit__(None, None, None)
    finally:
        xml_cm.__exit__(None, None, None)
        out_file.close()

    print(f"Классов: {len(best)}")
    print(f"Файл: {target}")
    print(f"Размер: {target.stat().st_size:,} байт")


if __name__ == "__main__":
    main()
