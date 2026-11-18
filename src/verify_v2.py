# -*- coding: utf-8 -*-
"""Верификация вывода cim_anonymizer_v2: граф, утечки, классы, PI, вложения."""
import base64
import io
import random
import re
import zipfile
from collections import Counter
from lxml import etree

RDF = "{http://www.w3.org/1999/02/22-rdf-syntax-ns#}"
RDF_ABOUT = RDF + "about"
RDF_RESOURCE = RDF + "resource"

INP = "./data/input.xml"
OUT = "./output/output.xml"

LEAK_PROBES = [
    "Чулпаново", "Тимошкино", "Новошешминск", "Аксубаево", "Ивашкино",
    "Киязлы", "Тимерлик", "Mali", "Djikoroni", "Nikitin", "Vitaliy",
    "ck11user5", "ck11service", "customer_50007178",
    "Equivalent of Global Objects", "Штаб ЕЭСК",
]
FIO_RE = re.compile(r"^[А-ЯЁ][а-яё]+ [А-ЯЁ][а-яё]+ [А-ЯЁ][а-яё]+$")
UUID_RE = re.compile(r"#_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")


def iter_top(path):
    for _, elem in etree.iterparse(path, events=("end",), huge_tree=True):
        par = elem.getparent()
        if par is not None and par.tag == RDF + "RDF":
            yield elem
            elem.clear()
            while elem.getprevious() is not None:
                del elem.getparent()[0]


def pass_abouts(path):
    return {el.get(RDF_ABOUT) for el in iter_top(path) if el.get(RDF_ABOUT)}


def pass_refs(path, abouts):
    total = dang = 0
    ex = []
    for elem in iter_top(path):
        for el in elem.iter():
            r = el.get(RDF_RESOURCE)
            if r:
                total += 1
                if r.startswith("#") and r not in abouts:
                    dang += 1
                    if len(ex) < 5:
                        ex.append(r)
    return total, dang, ex


def classes_and_names(path):
    classes = Counter()
    names = Counter()
    for elem in iter_top(path):
        classes[etree.QName(elem).localname] += 1
        for el in elem.iter():
            t = el.tag
            if isinstance(t, str):
                loc = t.rsplit("}", 1)[-1]
                if loc.endswith(".name") and el.text and el.text.strip():
                    names[el.text.strip()] += 1
    return classes, names


print("INPUT pass_abouts...")
in_abouts = pass_abouts(INP)
print("INPUT refs...")
in_total, in_dang, _ = pass_refs(INP, in_abouts)
print(f"  исходник: about={len(in_abouts)}, refs={in_total}, висячих={in_dang}")

print("OUTPUT pass_abouts...")
out_abouts = pass_abouts(OUT)
print("OUTPUT refs...")
out_total, out_dang, ex = pass_refs(OUT, out_abouts)
print(f"  вывод: about={len(out_abouts)}, refs={out_total}, висячих={out_dang} {ex[:3]}")
leak_ids = len(out_abouts & in_abouts)
print(f"  утечка идентификаторов: {leak_ids} из {len(out_abouts)}")

print("Классы и имена (двумя проходами по обоим файлам)...")
in_cls, _ = classes_and_names(INP)
out_cls, out_names = classes_and_names(OUT)
print(f"  классы совпадают: {in_cls == out_cls} ({len(in_cls)} классов)")
print(f"  различных name-значений: вывод={len(out_names)} (в исходнике было 120062)")

# утечки текстовых значений по пробам (только XML-тексты)
print("Утечки в XML-текстах (пробы)...")
hits = Counter()
for elem in iter_top(OUT):
    for el in elem.iter():
        t = el.tag
        if isinstance(t, str) and el.text:
            s = el.text
            if len(s) > 120:  # base64-поля проверяем отдельно по декодированию
                continue
            for p in LEAK_PROBES:
                if p in s:
                    hits[p] += 1
print("  остатки:", dict(hits) if hits else "нет")

# утечки внутри вложений: выборка 300 attachment'ов
print("Утечки внутри вложений (выборка 300)...")
random.seed(42)
checked = 0
bad = Counter()
for elem in iter_top(OUT):
    if checked >= 300:
        break
    for el in elem.iter():
        t = el.tag
        if not isinstance(t, str):
            continue
        loc = t.rsplit("}", 1)[-1]
        if loc in ("MonitelDiagram.image", "ACLineSegment.sections") and el.text and len(el.text) > 100:
            try:
                raw = base64.b64decode(el.text)
            except Exception:
                continue
            chunks = []
            if raw[:2] == b"PK":
                try:
                    with zipfile.ZipFile(io.BytesIO(raw)) as z:
                        for n in z.namelist():
                            if n.lower().endswith((".xml", ".txt")):
                                chunks.append(z.read(n))
                except Exception:
                    bad["zip_error"] += 1
            else:
                chunks.append(raw)
            for d in chunks:
                try:
                    txt = d.decode("utf-8", errors="ignore")
                except Exception:
                    continue
                for p in LEAK_PROBES:
                    if p in txt:
                        bad[p] += 1
            checked += 1
    elem.clear()
    while elem.getprevious() is not None:
        del elem.getparent()[0]
print(f"  проверено вложений: {checked}, остатки:", dict(bad) if bad else "нет")

# PI и пролог
with open(OUT, "rb") as f:
    head = f.read(600)
print("Пролог вывода:")
print(" ", head.decode("utf-8", errors="replace")[:400])
