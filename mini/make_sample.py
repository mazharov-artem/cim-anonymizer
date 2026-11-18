#!/usr/bin/env python3
"""Создание компактного образца большого CIM/RDF XML.

Скрипт читает исходный файл потоково через lxml.iterparse, поэтому
оперативная память не зависит от размера файла.

Что сохраняется в образце:
  * корневой элемент и все объявленные пространства имён;
  * по одному примеру на каждый уникальный "структурный отпечаток"
    верхнеуровневого объекта (набор тегов, атрибутов и вложенных структур);
  * внутри примера повторяющиеся однотипные дочерние элементы обрезаются
    до --max-children (структура при этом не теряется).

Дополнительно формируется текстовый отчёт со всеми путями, счётчиками
и списками атрибутов.
"""

from __future__ import annotations

import argparse
import copy
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

from lxml import etree

sys.setrecursionlimit(100_000)


def local_name(tag: str) -> str:
    """Возвращает локальную часть QName."""
    if not isinstance(tag, str):
        return str(tag)
    if tag.startswith("{"):
        return tag.split("}", 1)[1]
    return tag


def build_prefix_maps(nsmap: dict[str | None, str]):
    uri_to_prefix: dict[str, str] = {}
    for prefix, uri in nsmap.items():
        # None — пространство имён по умолчанию.
        uri_to_prefix.setdefault(uri, prefix or "")
    return uri_to_prefix


def readable_qname(tag: str, uri_to_prefix: dict[str, str]) -> str:
    if not isinstance(tag, str):
        return str(tag)
    if tag.startswith("{"):
        uri, local = tag[1:].split("}", 1)
        prefix = uri_to_prefix.get(uri)
        if prefix is None:
            return local
        return f"{prefix}:{local}" if prefix else local
    return tag


def shape(elem) -> tuple | None:
    """Структурный отпечаток элемента.

    Значения текста и атрибутов намеренно не учитываются — важна только
    структура. Повторяющиеся дочерние элементы схлопываются в множество,
    поэтому разное количество однотипных детей не плодит отпечатки.
    """
    tag = elem.tag
    if not isinstance(tag, str):
        return None

    attrs = tuple(sorted(elem.attrib.keys()))
    children: set[tuple] = set()
    for child in elem:
        child_shape = shape(child)
        if child_shape is not None:
            children.add(child_shape)
    return (tag, attrs, frozenset(children))


def prune(elem, max_children: int) -> None:
    """Оставляет не более max_children детей с одинаковым отпечатком."""
    groups: dict[tuple | None, list] = defaultdict(list)
    for child in elem:
        groups[shape(child)].append(child)

    for children in groups.values():
        for extra in children[max_children:]:
            elem.remove(extra)

    for child in elem:
        if isinstance(child.tag, str):
            prune(child, max_children)


def format_path(path: tuple[str, ...], uri_to_prefix: dict[str, str]) -> str:
    return " > ".join(readable_qname(tag, uri_to_prefix) for tag in path)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="data/input.xml", help="исходный XML")
    parser.add_argument(
        "--output", default="data/input_sample.xml", help="куда писать образец"
    )
    parser.add_argument(
        "--report", default="data/input_sample_report.txt", help="куда писать отчёт"
    )
    parser.add_argument(
        "--max-per-tag",
        type=int,
        default=10,
        help="максимум примеров на один верхнеуровневый тег (по отпечаткам)",
    )
    parser.add_argument(
        "--max-children",
        type=int,
        default=2,
        help="максимум однотипных дочерних элементов внутри примера",
    )
    parser.add_argument(
        "--stats-only",
        action="store_true",
        help="только собрать статистику, образец не писать",
    )
    parser.add_argument(
        "--progress-every",
        type=int,
        default=200_000,
        help="печатать прогресс каждые N верхнеуровневых объектов",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    report_path = Path(args.report)

    if not input_path.exists():
        raise SystemExit(f"Нет такого файла: {input_path}")

    started = time.time()

    nsmap: dict[str | None, str] = {}
    root_tag: str | None = None
    root_attrib: dict[str, str] = {}
    root_elem = None

    tag_stack: list[str] = []
    max_depth = 0

    path_counts: Counter[tuple[str, ...]] = Counter()
    path_attrs: dict[tuple[str, ...], set[str]] = defaultdict(set)

    top_tag_counts: Counter[str] = Counter()
    top_tag_signatures: dict[str, set[tuple]] = defaultdict(set)
    top_tag_examples: Counter[str] = Counter()
    top_tag_truncated: Counter[str] = Counter()
    total_nodes = 0
    total_top_level = 0

    sample_bytes = 0
    examples_written = 0

    output_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    out_file = None
    xml_cm = None
    xml_file = None
    root_ctx = None

    if not args.stats_only:
        out_file = output_path.open("wb")
        xml_cm = etree.xmlfile(out_file, encoding="utf-8")
        xml_file = xml_cm.__enter__()
        xml_file.write_declaration()

    try:
        context = etree.iterparse(
            str(input_path),
            events=("start-ns", "start", "end"),
            huge_tree=True,
            resolve_entities=False,
        )

        for event, payload in context:
            if event == "start-ns":
                prefix, uri = payload
                nsmap.setdefault(prefix, uri)
                continue

            if event == "start":
                elem = payload
                if root_tag is None:
                    root_elem = elem
                    root_tag = elem.tag
                    root_attrib = dict(elem.attrib)
                tag_stack.append(elem.tag)
                if len(tag_stack) > max_depth:
                    max_depth = len(tag_stack)
                continue

            # event == "end"
            elem = payload
            total_nodes += 1

            path = tuple(tag_stack)
            path_counts[path] += 1
            path_attrs[path].update(elem.attrib.keys())

            parent = elem.getparent()
            if parent is not None and parent is root_elem:
                total_top_level += 1
                top_tag_counts[elem.tag] += 1

                sig = shape(elem)
                is_new_shape = sig not in top_tag_signatures[elem.tag]
                top_tag_signatures[elem.tag].add(sig)

                if not args.stats_only and is_new_shape:
                    if top_tag_examples[elem.tag] < args.max_per_tag:
                        example = copy.deepcopy(elem)
                        prune(example, args.max_children)

                        if root_ctx is None:
                            root_ctx = xml_file.element(
                                root_tag, attrib=root_attrib, nsmap=nsmap
                            )
                            root_ctx.__enter__()

                        sample_bytes += len(etree.tostring(example))
                        xml_file.write(example)
                        examples_written += 1
                        top_tag_examples[elem.tag] += 1
                    else:
                        top_tag_truncated[elem.tag] += 1

                # Освобождаем память.
                elem.clear()
                while elem.getprevious() is not None:
                    del parent[0]

                if (
                    args.progress_every
                    and total_top_level % args.progress_every == 0
                ):
                    elapsed = time.time() - started
                    print(
                        f"обработано объектов: {total_top_level:,} "
                        f"({elapsed:.1f} c)",
                        flush=True,
                    )

            tag_stack.pop()

    finally:
        if root_ctx is not None:
            root_ctx.__exit__(None, None, None)
        if xml_cm is not None:
            xml_cm.__exit__(None, None, None)
        if out_file is not None:
            out_file.close()

    elapsed = time.time() - started
    uri_to_prefix = build_prefix_maps(nsmap)

    # ---------------- отчёт ----------------
    lines: list[str] = []
    lines.append("ОТЧЁТ О СТРУКТУРЕ XML")
    lines.append("=" * 80)
    lines.append(f"Исходный файл: {input_path}")
    lines.append(f"Размер файла: {input_path.stat().st_size:,} байт")
    lines.append(f"Время разбора: {elapsed:.1f} c")
    lines.append(f"Всего элементов: {total_nodes:,}")
    lines.append(f"Верхнеуровневых объектов: {total_top_level:,}")
    lines.append(f"Максимальная глубина: {max_depth}")
    lines.append(f"Корневой элемент: {readable_qname(root_tag, uri_to_prefix)}")
    if root_attrib:
        lines.append("Атрибуты корня:")
        for key, value in root_attrib.items():
            lines.append(f"  {readable_qname(key, uri_to_prefix)}={value!r}")
    lines.append("")

    lines.append("Пространства имён:")
    for prefix, uri in sorted(nsmap.items(), key=lambda x: (x[0] or "")):
        lines.append(f"  {prefix or '(default)'}: {uri}")
    lines.append("")

    lines.append("Верхнеуровневые теги (классы объектов):")
    lines.append(
        f"  {'тег':<60} {'всего':>12} {'уник. структур':>15} "
        f"{'в образце':>10}"
    )
    for tag, count in top_tag_counts.most_common():
        lines.append(
            f"  {readable_qname(tag, uri_to_prefix):<60} {count:>12,} "
            f"{len(top_tag_signatures[tag]):>15,} {top_tag_examples[tag]:>10,}"
        )
    lines.append("")

    truncated = {
        tag: count for tag, count in top_tag_truncated.items() if count > 0
    }
    if truncated:
        lines.append(
            "ВНИМАНИЕ: для части тегов достигнут лимит --max-per-tag, "
            "не все уникальные структуры попали в образец:"
        )
        for tag, count in sorted(truncated.items(), key=lambda x: -x[1]):
            lines.append(
                f"  {readable_qname(tag, uri_to_prefix)}: "
                f"пропущено отпечатков {count:,}"
            )
        lines.append("")

    lines.append("Все пути элементов (путь > количество > атрибуты):")
    for path in sorted(path_counts, key=lambda p: (len(p), p)):
        attrs = sorted(
            readable_qname(a, uri_to_prefix) for a in path_attrs.get(path, ())
        )
        attr_text = ", ".join(attrs) if attrs else "—"
        lines.append(
            f"  {format_path(path, uri_to_prefix)} > "
            f"{path_counts[path]:,} > {attr_text}"
        )
    lines.append("")

    if not args.stats_only:
        lines.append("ОБРАЗЕЦ")
        lines.append("-" * 80)
        lines.append(f"Файл образца: {output_path}")
        lines.append(f"Записано примеров: {examples_written:,}")
        lines.append(f"Оценка размера образца: {sample_bytes:,} байт")
        lines.append(f"Фактический размер: {output_path.stat().st_size:,} байт")

    report_path.write_text("\n".join(lines), encoding="utf-8")

    print(f"Готово за {elapsed:.1f} c")
    print(f"Отчёт: {report_path}")
    if not args.stats_only:
        print(f"Образец: {output_path}")
        print(f"Примеров: {examples_written:,}")
        print(f"Размер образца: {output_path.stat().st_size:,} байт")


if __name__ == "__main__":
    main()
