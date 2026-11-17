# src/main.py
import argparse
import hashlib
import hmac

from lxml import etree

SECRET = b"super-secret-key-change-me-1234567890"

RDF_NS = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
RDF_ABOUT = f"{{{RDF_NS}}}about"
RDF_RESOURCE = f"{{{RDF_NS}}}resource"
RDF_RDF = f"{{{RDF_NS}}}RDF"

def _h(*parts: str) -> str:
    return hmac.new(SECRET, "|".join(parts).encode("utf-8"), hashlib.sha256).hexdigest()

def new_id(old: str) -> str:
    raw = old.lstrip("#_")
    hx = _h("id", raw)
    return "#_" + f"{hx[:8]}-{hx[8:12]}-{hx[12:16]}-{hx[16:20]}-{hx[20:32]}"

ADJ = [
    "Яблочный", "Грушевый", "Сливовый", "Вишнёвый", "Абрикосовый",
    "Персиковый", "Виноградный", "Арбузный", "Дынный", "Ананасовый",
    "Манговый", "Лимонный", "Апельсиновый", "Мандариновый", "Банановый",
    "Картофельный", "Морковный", "Свекольный", "Тыквенный", "Огуречный",
]

def new_name(old_text: str, cls: str) -> str:
    idx = int(_h("adj", old_text), 16) % len(ADJ)
    sfx = _h("sfx", old_text)[:6].upper()
    return f"{ADJ[idx]} {cls}-{sfx}"

def read_nsmap(path: str) -> dict:
    """Собирает объявления namespace из корневого элемента документа.

    Читаем потоково и останавливаемся сразу после открытия корня: все
    объявления xmlns находятся в нём, поэтому парсить (или обрезать по
    байтам) весь файл не нужно.
    """
    nsmap: dict = {}
    for event, payload in etree.iterparse(path, events=("start-ns", "start")):
        if event == "start-ns":
            prefix, uri = payload
            nsmap.setdefault(prefix, uri)
        else:
            break
    return nsmap

def anonymize_element(elem) -> None:
    about = elem.get(RDF_ABOUT)
    if about and about.startswith("#_"):
        elem.set(RDF_ABOUT, new_id(about))

    for el in elem.iter():
        res = el.get(RDF_RESOURCE)
        if res and res.startswith("#_"):
            el.set(RDF_RESOURCE, new_id(res))

    cls = etree.QName(elem).localname
    for el in elem.iter():
        local = etree.QName(el).localname
        
        # Пропускаем системные поля модели, чтобы не менять CIM16 и даты
        if local in ("Model.name", "Model.version", "Model.created"):
            continue
            
        # Отрезаем префикс класса, чтобы отловить "IdentifiedObject.name" -> "name"
        field = local.split(".")[-1]
        
        if field in ("name", "aliasName", "description", "dispatchName") and el.text:
            txt = el.text.strip()
            if txt:
                el.text = new_name(txt, cls)

def process(input_path: str, output_path: str) -> None:
    nsmap = read_nsmap(input_path)
    count = 0
    with etree.xmlfile(output_path, encoding="utf-8") as xf:
        xf.write_declaration()
        with xf.element(RDF_RDF, nsmap=nsmap):
            for _, elem in etree.iterparse(input_path, events=("end",), huge_tree=True):
                parent = elem.getparent()
                if parent is None or parent.tag != RDF_RDF:
                    continue
                anonymize_element(elem)
                xf.write(elem)
                parent.remove(elem)
                elem.clear()
                count += 1
    print(f"OK: {count} объектов -> {output_path}")

if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--input", required=True)
    ap.add_argument("--output", required=True)
    args = ap.parse_args()
    process(args.input, args.output)