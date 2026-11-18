#!/usr/bin/env python3
"""Проверка, что образец покрывает структуру исходного файла.

Сравнение идёт с текстовым отчётом, собранным по оригиналу:
  * все верхнеуровневые теги;
  * все пути элементов;
  * все имена атрибутов на каждом пути.
"""

from __future__ import annotations

import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

from lxml import etree


def parse_report(path: Path):
    lines = path.read_text(encoding="utf-8").splitlines()

    top_start = lines.index("Верхнеуровневые теги (классы объектов):") + 2
    path_start = lines.index("Все пути элементов (путь > количество > атрибуты):")

    top_tags: set[str] = set()
    top_counts: dict[str, int] = {}

    for line in lines[top_start:path_start]:
        m = re.match(r"\s+(\S+)\s+([\d,]+)\s+([\d,]+)\s+([\d,]+)\s*$", line)
        if m:
            tag = m.group(1)
            top_tags.add(tag)
            top_counts[tag] = int(m.group(2).replace(",", ""))

    paths: set[str] = set()
    attrs_by_path: dict[str, set[str]] = defaultdict(set)

    for line in lines[path_start + 1 :]:
        if not line.startswith("  "):
            continue
        body = line[2:]
        if " > " not in body:
            continue
        path_text, count_text, attrs_text = body.rsplit(" > ", 2)
        if not count_text.replace(",", "").isdigit():
            continue
        paths.add(path_text)
        if attrs_text != "—":
            attrs_by_path[path_text].update(
                a.strip() for a in attrs_text.split(",") if a.strip()
            )

    return top_tags, top_counts, paths, attrs_by_path


def readable_qname(tag: str, uri_to_prefix: dict[str, str]) -> str:
    if not tag.startswith("{"):
        return tag
    uri, local = tag[1:].split("}", 1)
    prefix = uri_to_prefix.get(uri)
    return f"{prefix}:{local}" if prefix else local


def collect_sample(path: Path):
    nsmap: dict[str | None, str] = {}
    tag_stack: list[str] = []
    top_counts: Counter[str] = Counter()
    paths: set[str] = set()
    attrs_by_path: dict[str, set[str]] = defaultdict(set)
    root_tag = None
    root_elem = None

    for event, payload in etree.iterparse(
        str(path), events=("start-ns", "start", "end"), huge_tree=True
    ):
        if event == "start-ns":
            prefix, uri = payload
            nsmap.setdefault(prefix, uri)
        elif event == "start":
            elem = payload
            if root_tag is None:
                root_tag = elem.tag
                root_elem = elem
            tag_stack.append(elem.tag)
        else:
            elem = payload
            parent = elem.getparent()
            if parent is not None and parent is root_elem:
                top_counts[elem.tag] += 1

            # В отчёте пути записаны через читаемые QName. Для сравнения
            # переводим полные QName образца в тот же вид.
            uri_to_prefix = {}
            for prefix, uri in nsmap.items():
                uri_to_prefix.setdefault(uri, prefix or "")

            parts = []
            for tag in tag_stack:
                if tag.startswith("{"):
                    uri, local = tag[1:].split("}", 1)
                    prefix = uri_to_prefix.get(uri)
                    parts.append(
                        f"{prefix}:{local}" if prefix else local
                    )
                else:
                    parts.append(tag)
            path_text = " > ".join(parts)
            paths.add(path_text)

            for attr in elem.attrib:
                if attr.startswith("{"):
                    uri, local = attr[1:].split("}", 1)
                    prefix = uri_to_prefix.get(uri)
                    attrs_by_path[path_text].add(
                        f"{prefix}:{local}" if prefix else local
                    )
                else:
                    attrs_by_path[path_text].add(attr)

            tag_stack.pop()

    uri_to_prefix = {}
    for prefix, uri in nsmap.items():
        uri_to_prefix.setdefault(uri, prefix or "")

    top_counts = Counter(
        {
            readable_qname(tag, uri_to_prefix): count
            for tag, count in top_counts.items()
        }
    )
    root_tag = readable_qname(root_tag, uri_to_prefix)

    return nsmap, root_tag, top_counts, paths, attrs_by_path


def main() -> None:
    report = Path(sys.argv[1] if len(sys.argv) > 1 else "data/input_sample_report.txt")
    sample = Path(sys.argv[2] if len(sys.argv) > 2 else "data/input_sample.xml")

    orig_tags, orig_counts, orig_paths, orig_attrs = parse_report(report)
    nsmap, root_tag, sample_counts, sample_paths, sample_attrs = collect_sample(sample)

    missing_tags = sorted(orig_tags - set(sample_counts))
    extra_tags = sorted(set(sample_counts) - orig_tags)
    missing_paths = sorted(orig_paths - sample_paths)
    extra_paths = sorted(sample_paths - orig_paths)

    missing_attrs = []
    for path in orig_paths:
        missing = orig_attrs.get(path, set()) - sample_attrs.get(path, set())
        if missing:
            missing_attrs.append((path, sorted(missing)))

    print(f"Корневой тег образца: {root_tag}")
    print(f"Пространств имён: {len(nsmap)}")
    print(f"Верхнеуровневых тегов в оригинале: {len(orig_tags)}")
    print(f"Верхнеуровневых тегов в образце:   {len(sample_counts)}")
    print(f"Уникальных путей в оригинале: {len(orig_paths)}")
    print(f"Уникальных путей в образце:   {len(sample_paths)}")

    ok = True
    if missing_tags:
        ok = False
        print(f"\nНЕТ ТЕГОВ ({len(missing_tags)}):")
        for tag in missing_tags:
            print(f"  {tag}")
    if extra_tags:
        ok = False
        print(f"\nЛИШНИЕ ТЕГИ ({len(extra_tags)}):")
        for tag in extra_tags:
            print(f"  {tag}")
    if missing_paths:
        ok = False
        print(f"\nНЕТ ПУТЕЙ ({len(missing_paths)}):")
        for path in missing_paths[:50]:
            print(f"  {path}")
        if len(missing_paths) > 50:
            print(f"  ... и ещё {len(missing_paths) - 50}")
    if extra_paths:
        ok = False
        print(f"\nЛИШНИЕ ПУТИ ({len(extra_paths)}):")
        for path in extra_paths[:50]:
            print(f"  {path}")
        if len(extra_paths) > 50:
            print(f"  ... и ещё {len(extra_paths) - 50}")
    if missing_attrs:
        ok = False
        print(f"\nНЕТ АТРИБУТОВ НА ПУТЯХ ({len(missing_attrs)}):")
        for path, attrs in missing_attrs[:50]:
            print(f"  {path}: {', '.join(attrs)}")
        if len(missing_attrs) > 50:
            print(f"  ... и ещё {len(missing_attrs) - 50}")

    if ok:
        print("\nOK: образец содержит все теги, пути и атрибуты оригинала.")
    else:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
