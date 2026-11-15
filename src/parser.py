# src/parser.py
from __future__ import annotations
import io
from lxml import etree

RDF_NS = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
RDF_ABOUT = f"{{{RDF_NS}}}about"
RDF_RESOURCE = f"{{{RDF_NS}}}resource"
RDF_RDF = f"{{{RDF_NS}}}RDF"


def read_namespaces(path: str) -> dict[str, str]:
    """Читает только первые ~64КБ, чтобы собрать nsmap для xmlfile."""
    with open(path, "rb") as f:
        head = f.read(65536)

    nsmap: dict[str, str] = {}
    # iterparse на куске: start-ns даёт (prefix, uri)
    for event, payload in etree.iterparse(io.BytesIO(head), events=("start-ns",)):
        prefix, uri = payload
        if prefix not in nsmap:
            nsmap[prefix] = uri
    return nsmap


def iter_top_level(path: str):
    """Отдаёт верхнеуровневые элементы <rdf:RDF>.../... один за другим."""
    for _, elem in etree.iterparse(path, events=("end",), huge_tree=True):
        parent = elem.getparent()
        if parent is not None and parent.tag == RDF_RDF:
            yield elem


def transform(input_path: str, output_path: str, anonymize_fn) -> None:
    nsmap = read_namespaces(input_path)

    with etree.xmlfile(output_path, encoding="utf-8") as xf:
        xf.write_declaration()
        with xf.element(RDF_RDF, nsmap=nsmap):
            for elem in iter_top_level(input_path):
                anonymize_fn(elem)
                xf.write(elem)
                # освобождаем память
                elem.getparent().remove(elem)
                elem.clear()