#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
cim_anonymizer_v2 — потоковое обезличивание CIM RDF XML (МЭК 61970-301 / 61968-11) по ТЗ.

Соответствие ТЗ:
  * Абоненты-физлица / сотрудники (Customer, Person)  -> синтетические ФИО из справочника,
    email и улицы генерируются из того же синтетического имени.
  * Абоненты-юрлица / энергообъекты                   -> «овощ/фрукт -> прилагательное +
    класс объекта + суффикс» (ТП остаётся ТП, ПС — ПС, класс в имени сохраняется).
  * Цифровые идентификаторы (mRID, mRIDStr, serialNumber, Asset.type, ccsCode, ИНН/КПП,
    табельные и пр.) -> числовые последовательности той же длины; общий кэш сохраняет
    связность ссылок (число -> одно и то же число везде).
  * UUID-идентификаторы (rdf:about / rdf:resource, Location.fiasId) -> детерминированный
    BLAKE2b(key=SECRET) -> новый UUID, без ключа не восстанавливается.
  * Свободные поля (description, тексты шаблонов) -> маскирование упоминаний реальных
    наименований (по справочнику собранных имён) + ПДн-паттерны (email, телефон,
    ФИО с инициалами, паспорт, СНИЛС).
  * Вложения: MonitelDiagram.image (ZIP с diagram.xml) и ACLineSegment.sections
    (base64-XML) маскируются изнутри; Icon (PNG) не изменяется.
  * Детерминированность между запусками, ссылочная целостность (граф идентичен
    исходному с точностью до переименования вершин), статистика значений сохранена
    (различные значения -> различные новые, одинаковые -> одинаковые).
  * Потоковая обработка (iterparse + очистка памяти) — файлы до десятков ГБ.
  * PI-инструкции экспортёра (<?iec61970-552?>, <?floatExporter?>) и корневые xmlns
    сохраняются; вывод НЕ раздувается xmlns-декларациями на каждом объекте.

Запуск:
  python3 cim_anonymizer_v2.py --input input.xml --output output.xml
Ключ детерминированности: переменная окружения ANON_SECRET или файл ключа
(--secret-file, по умолчанию создаётся рядом с результатом, права 0600).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import io
import os
import re
import sys
import time
import zipfile
from collections import Counter
from pathlib import Path

from lxml import etree

RDF_NS = "http://www.w3.org/1999/02/22-rdf-syntax-ns#"
RDF = "{%s}" % RDF_NS
RDF_ABOUT = RDF + "about"
RDF_RESOURCE = RDF + "resource"
RDF_RDF = RDF + "RDF"

UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
TOKEN_RE = re.compile(r"[0-9A-Za-zА-Яа-яЁё]+")
DIGITS_RE = re.compile(r"\d+")
_CYR_RE = re.compile(r"[А-Яа-яЁё]")
ATTR_RE = re.compile(r'([A-Za-z]+)="([^"]*)"')


def _has_cyr(s: str) -> bool:
    return _CYR_RE.search(s) is not None

# ----------------------------------------------------------------------------
# Классификация полей (по фактическому содержимому моделей КТС Мониторинг)
# ----------------------------------------------------------------------------

# наименования объектов (последний сегмент локального имени тега)
NAME_LAST = {
    "name", "aliasname", "nameplate", "foldername", "classname",
    "dispatchname", "locname",
}
# числовые/идентификационные поля (последний сегмент, в нижнем регистре)
ID_LAST = {
    "mrid", "mridstr", "serialnumber", "ccscode", "fiasid", "fiasstreetid",
    "tabnumber", "personalnumber", "passportnumber", "accountnumber",
    "phonenumber", "inn", "kpp", "okpo", "buildingname",
}
# полные локальные имена идентификационных полей
ID_FULL = {"asset.type"}
# свободные текстовые поля
FREE_LAST = {"description", "text", "texttemplate", "comment", "notes"}
# поля адресов классов TownDetail
ADDR_LAST = {"stateorprovince", "country"}
# вложения (полное локальное имя тега)
ATTACH_FIELDS = {"moniteldiagram.image", "aclinesegment.sections"}
# классы-особые
PERSON_CLASSES = {"person"}          # учётные записи сотрудников
CUSTOMER_CLASSES = {"customer"}      # абоненты (ФИО)
STREET_CLASSES = {"streetdetail"}
TOWN_CLASSES = {"towndetail"}
SKIP_TEXT_CLASSES = {"fullmodel"}    # метаданные модели не трогаем

# маскируемые атрибуты внутри вложений-XML
DIAG_MASK_ATTRS = {
    "Description", "Name", "name", "ElementName", "Text", "ItemName",
    "Label", "Caption", "Nameplate", "nameplate", "Comment", "TextValue",
    "title", "Title", "label",
}
# атрибуты, для которых дополнительно маскируются цифры (заводские марки)
DIAG_DIGIT_ATTRS = {"Nameplate", "nameplate"}

# ----------------------------------------------------------------------------
# Справочники (все синтетические, детерминированные)
# ----------------------------------------------------------------------------

FRUIT_VEG_ADJ = [
    "Яблочный", "Грушевый", "Сливовый", "Вишнёвый", "Абрикосовый",
    "Персиковый", "Виноградный", "Арбузный", "Дынный", "Ананасовый",
    "Манговый", "Лимонный", "Апельсиновый", "Мандариновый", "Банановый",
    "Гранатовый", "Оливковый", "Картофельный", "Морковный", "Свекольный",
    "Тыквенный", "Огуречный", "Томатный", "Капустный", "Луковый",
    "Чесночный", "Редисочный", "Гороховый", "Фасолевый", "Кукурузный",
    "Пшеничный", "Ржаной", "Овсяный", "Ячменный", "Рисовый",
    "Гречишный", "Просовый", "Кунжутный", "Арахисовый", "Клюквенный",
]

_SURNAMES = [
    "Яблочкин", "Грушин", "Сливков", "Вишневский", "Абрикосов", "Персиков",
    "Виноградов", "Арбузкин", "Дынин", "Ананасьев", "Манго", "Лимонов",
    "Апельсинов", "Мандаринов", "Бананов", "Гранатов", "Оливин",
    "Картошкин", "Морковин", "Свеклов", "Тыквин", "Огурцов", "Томатин",
    "Капустин", "Луков", "Чесноков", "Редискин", "Горохов", "Фасолин",
    "Кукурузин", "Пшенин", "Ржанов", "Овсянников", "Ячменев", "Рисов",
    "Гречишников", "Просов", "Кунжутов", "Арахисов", "Клюквин",
    "Брусникин", "Крыжовников", "Смородинов", "Малинин", "Земляникин",
    "Черникин", "Айвов", "Инжирин", "Фиников", "Хурмин", "Нектаринов",
    "Дынников", "Патиссонов", "Пастернаков", "Ревенев", "Спаржин",
    "Щавелев", "Хренов", "Репин", "Редечкин", "Дайконин", "Порей",
]

MALE_NAMES = [
    "Пётр", "Иван", "Степан", "Андрей", "Николай", "Сергей", "Алексей",
    "Дмитрий", "Михаил", "Владимир", "Василий", "Григорий", "Фёдор",
    "Борис", "Артём", "Олег", "Павел", "Роман", "Юрий", "Максим",
    "Егор", "Тимофей", "Данил", "Кирилл", "Игорь", "Антон", "Виктор",
    "Глеб", "Денис", "Евгений", "Семён", "Константин", "Леонид",
    "Тарас", "Филипп", "Марк", "Захар", "Макар", "Савва", "Трофим",
    "Лука", "Мирон", "Никита", "Яков", "Матвей", "Елисей", "Родион",
    "Аркадий", "Всеволод", "Платон",
]

PATRONYMICS = [
    "Петрович", "Иванович", "Степанович", "Андреевич", "Николаевич",
    "Сергеевич", "Алексеевич", "Дмитриевич", "Михайлович", "Владимирович",
    "Васильевич", "Григорьевич", "Фёдорович", "Борисович", "Артёмович",
    "Олегович", "Павлович", "Романович", "Юрьевич", "Максимович",
    "Егорович", "Тимофеевич", "Данилович", "Кириллович", "Игоревич",
    "Антонович", "Викторович", "Глебович", "Денисович", "Евгеньевич",
    "Семёнович", "Константинович", "Леонидович", "Тарасович",
    "Филиппович", "Маркович", "Захарович", "Макарович", "Саввич",
    "Трофимович", "Лукич", "Миронович", "Никитич", "Яковлевич",
    "Матвеевич", "Елисеевич", "Родионович", "Аркадьевич",
    "Всеволодович", "Платонович",
]

_TOWN_STEMS = [
    "Яблонов", "Грушев", "Сливов", "Вишнёв", "Абрикосов", "Персиков",
    "Виноград", "Арбузов", "Дын", "Ананасов", "Мангов", "Лимонов",
    "Апельсин", "Мандарин", "Бананов", "Гранатов", "Оливов", "Морков",
    "Свеклов", "Тыкв", "Огурцов", "Томат", "Капуст", "Луков",
    "Чесноков", "Редисов", "Горохов", "Фасолов", "Кукуруз", "Пшен",
    "Ржан", "Овсян", "Ячмен", "Рисов", "Гречиш", "Просов", "Кунжут",
    "Арахисов", "Клюквин", "Брусников",
]
_TOWN_ENDS = ["овка", "ино", "ово", "инск", "град", "поль", "ярск", "горск"]

TOWNS = []
for _s in _TOWN_STEMS:
    for _e in _TOWN_ENDS:
        TOWNS.append(_s + _e)
TOWNS = sorted(set(TOWNS))

COUNTRIES = sorted({
    _s.rstrip("ов") + "ия" for _s in _TOWN_STEMS
} | {"Яблония", "Грушевия", "Сливония", "Вишневия", "Морковия"})

STREET_TYPES = ["ул.", "пер.", "пр-кт", "проезд", "б-р"]

WORD_POOL = sorted(set(TOWNS) | set(FRUIT_VEG_ADJ))

TRANSLIT = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e",
    "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "kh", "ц": "ts", "ч": "ch", "ш": "sh", "щ": "sch",
    "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
}


def translit(word: str) -> str:
    return "".join(TRANSLIT.get(ch, ch) for ch in word.lower())


# ----------------------------------------------------------------------------
# Ключ детерминированности и криптографические примитивы
# ----------------------------------------------------------------------------

KEY: bytes = b""


def load_secret(path: Path) -> bytes:
    env = os.environ.get("ANON_SECRET")
    if env:
        print("Ключ: из переменной окружения ANON_SECRET")
        return env.encode("utf-8")
    if path.exists():
        key = path.read_bytes().strip()
        if key:
            print(f"Ключ: файл {path}")
            return key
    key = os.urandom(48)
    path.write_bytes(key)
    os.chmod(path, 0o600)
    print(f"Ключ: создан новый файл {path} (сохраните его для воспроизводимости)")
    return key


def _h(salt: str, data: str, size: int = 16) -> bytes:
    return hashlib.blake2b(
        (salt + "|" + data).encode("utf-8"), key=KEY, digest_size=size
    ).digest()


def _hh(salt: str, data: str, size: int = 16) -> str:
    return hashlib.blake2b(
        (salt + "|" + data).encode("utf-8"), key=KEY, digest_size=size
    ).hexdigest()


# ----------------------------------------------------------------------------
# Замены: идентификаторы, числа, UUID, имена, ФИО, адреса
# ----------------------------------------------------------------------------

class Uniquer:
    """Биекция: различные исходные значения -> различные новые имена."""

    def __init__(self) -> None:
        self.used: set[str] = set()
        self.collisions = 0

    def claim(self, base: str, variants) -> str:
        if base not in self.used:
            self.used.add(base)
            return base
        self.collisions += 1
        for cand in variants:
            if cand not in self.used:
                self.used.add(cand)
                return cand
        k = 1
        while True:
            cand = f"{base} {k}"
            if cand not in self.used:
                self.used.add(cand)
                return cand
            k += 1


def synth_adj_sfx(old: str, salt: str = "name"):
    h = _hh(salt, old, 20)
    adj = FRUIT_VEG_ADJ[int(h[:8], 16) % len(FRUIT_VEG_ADJ)]
    return adj, h


def make_object_name(old: str, cls: str):
    """овощ/фрукт -> прилагательное + класс объекта + суффикс."""
    adj, h = synth_adj_sfx(old, "name")
    base = f"{adj} {cls}-{h[8:14].upper()}"
    variants = [f"{adj} {cls}-{h[8:16].upper()}", f"{adj} {cls}-{h[8:20].upper()}"]
    return base, variants


def synth_person_fio(old: str):
    h = _hh("person", old, 24)
    n = int(h, 16)
    fam = _SURNAMES[n % len(_SURNAMES)]
    name = MALE_NAMES[(n // len(_SURNAMES)) % len(MALE_NAMES)]
    mid = PATRONYMICS[(n // (len(_SURNAMES) * len(MALE_NAMES))) % len(PATRONYMICS)]
    base = f"{fam} {name} {mid}"
    variants = [
        f"{_SURNAMES[(n + k) % len(_SURNAMES)]} {name} {mid}" for k in range(1, 6)
    ]
    return base, variants


def synth_street(old: str):
    h = _hh("street", old, 16)
    n = int(h, 16)
    fam = _SURNAMES[n % len(_SURNAMES)]
    tp = STREET_TYPES[(n // len(_SURNAMES)) % len(STREET_TYPES)]
    base = f"{tp} {fam}а"
    variants = [
        f"{STREET_TYPES[(n // len(_SURNAMES) + k) % len(STREET_TYPES)]} "
        f"{_SURNAMES[(n + k) % len(_SURNAMES)]}а" for k in range(1, 6)
    ]
    return base, variants


def synth_town(old: str):
    h = _hh("town", old, 16)
    n = int(h, 16)
    base = TOWNS[n % len(TOWNS)]
    variants = [TOWNS[(n + k) % len(TOWNS)] for k in range(1, 6)]
    return base, variants


def synth_region(old: str):
    h = _hh("region", old, 16)
    n = int(h, 16)
    stem = _TOWN_STEMS[n % len(_TOWN_STEMS)]
    kind = ["район", "край", "область", "автономный округ"][
        (n // len(_TOWN_STEMS)) % 4
    ]
    if kind == "область":
        stem = stem.replace("ов", "овская").replace("ин", "инская")
    base = f"{stem} {kind}"
    variants = [f"{_TOWN_STEMS[(n + k) % len(_TOWN_STEMS)]} {kind}" for k in range(1, 6)]
    return base, variants


def synth_country(old: str):
    h = _hh("country", old, 16)
    n = int(h, 16)
    base = COUNTRIES[n % len(COUNTRIES)]
    variants = [COUNTRIES[(n + k) % len(COUNTRIES)] for k in range(1, 6)]
    return base, variants


def synth_word(old: str) -> str:
    h = _h("word", old, 8)
    return WORD_POOL[int.from_bytes(h, "big") % len(WORD_POOL)]


class Pseudonymizer:
    """Все кэши замен. Заполняется в pass1, используется в pass2."""

    def __init__(self) -> None:
        self.name_uniquer = Uniquer()
        self.person_uniquer = Uniquer()
        self.addr_uniquer = Uniquer()
        self.id_cache: dict[str, str] = {}       # raw uuid -> new uuid
        self.uuid_cache: dict[str, str] = {}     # прочие UUID (ФИАС и пр.)
        self.num_cache: dict[str, str] = {}      # число -> число той же длины
        self.phone_parts: dict[str, str] = {}    # цифровой фрагмент телефона
        self.name_map: dict[str, str] = {}
        self.person_map: dict[str, str] = {}     # ФИО -> ФИО
        self.person_obj: dict[str, dict] = {}    # about -> синтетические части
        self.street_map: dict[str, str] = {}
        self.town_map: dict[str, str] = {}
        self.region_map: dict[str, str] = {}
        self.country_map: dict[str, str] = {}
        self.att_val_map: dict[str, str] = {}    # значения атрибутов вложений
        self.att_words: set[str] = set()         # значимые слова из вложений
        self.fio_email_cache: dict[str, str] = {}
        self.exact_index: dict[str, list] = {}   # токен -> [(реальное, новое)]
        self.word_map: dict[str, str] = {}       # слово -> синтетическое слово
        self._text_cache: dict[str, str] = {}    # кэш маскирования (строки повторяются)
        self.stats = Counter()

    # ---- идентификаторы ----
    def map_uuid(self, raw: str) -> str:
        v = self.id_cache.get(raw)
        if v is None:
            h = _hh("id", raw, 16)
            v = f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
            self.id_cache[raw] = v
            self.stats["uuid"] += 1
        return v

    def map_uuid_value(self, s: str) -> str:
        v = self.uuid_cache.get(s)
        if v is None:
            h = _hh("uuid", s, 16)
            v = f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
            self.uuid_cache[s] = v
        return v

    def map_digits(self, digits: str) -> str:
        v = self.num_cache.get(digits)
        if v is None:
            n = len(digits)
            h = int.from_bytes(_h("num", digits, 8), "big")
            v = str(h % (10 ** n)).zfill(n)
            if v == digits:  # избегаем тождественной замены
                v = str((h + 1) % (10 ** n)).zfill(n)
            self.num_cache[digits] = v
            self.stats["num_distinct"] += 1
        return v

    def mask_digits(self, s: str) -> str:
        return DIGITS_RE.sub(lambda m: self.map_digits(m.group()), s)

    # ---- справочные значения ----
    def map_name(self, s: str) -> str:
        v = self.name_map.get(s)
        if v is None:  # значение не из pass1 (не должно случаться)
            cls = "Object"
            base, variants = make_object_name(s, cls)
            v = self.name_uniquer.claim(base, variants)
            self.name_map[s] = v
        return v

    def email_for_fio(self, fio: str) -> str:
        v = self.fio_email_cache.get(fio)
        if v is None:
            parts = fio.split()
            h = _hh("email", fio, 4).hex()
            v = f"{translit(parts[1])}.{translit(parts[0])}.{h}@example.test"
            self.fio_email_cache[fio] = v
        return v

    # ---- индекс маскирования свободного текста ----
    def build_text_index(self, name_counts: Counter, rare_limit: int = 50) -> None:
        exact: dict[str, list] = {}
        words: dict[str, list] = {}
        pairs: list[tuple[str, str]] = list(self.name_map.items())
        pairs += list(self.person_map.items())
        pairs += list(self.street_map.items())
        pairs += list(self.town_map.items())
        pairs += list(self.region_map.items())
        pairs += list(self.country_map.items())
        pairs += list(self.att_val_map.items())  # имена из вложений — без порога
        for real, repl in pairs:
            if not real:
                continue
            if name_counts.get(real, 1) > rare_limit and real not in self.att_val_map:
                continue  # технические частые значения ('Imax', 'switch device')
            first = TOKEN_RE.findall(real)
            if not first:
                continue
            exact.setdefault(first[0].lower(), []).append((real, repl))
            for tok in first:
                tl = tok.lower()
                if len(tl) >= 4 and tl not in words and _has_cyr(tl):
                    words[tl] = synth_word(tl)
        for tok in self.att_words:
            tl = tok.lower()
            if tl not in words:
                words[tl] = synth_word(tl)
        for key in exact:
            exact[key].sort(key=lambda p: -len(p[0]))
        self.exact_index = exact
        self.word_map = words

    # ---- маскирование свободного текста ----
    _email_re = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
    _phone_re = re.compile(r"(?:\+7|8)[\s\-(]*\d{3}[\s\-)]*\d{3}[\s\-]*\d{2}[\s\-]*\d{2}")
    _fio_re1 = re.compile(r"\b[А-ЯЁ][а-яё]+\s+[А-ЯЁ]\.\s?[А-ЯЁ]\.")
    _fio_re2 = re.compile(r"\b[А-ЯЁ]\.\s?[А-ЯЁ]\.\s?[А-ЯЁ][а-яё]+")
    _passport_re = re.compile(r"\b\d{4}\s\d{6}\b")
    _snils_re = re.compile(r"\b\d{3}-\d{3}-\d{3}\s\d{2}\b")

    def _pii_sub(self, s: str) -> str:
        s = self._email_re.sub(
            lambda m: f"user.{_hh('email', m.group(0), 4)}@example.test",
            s,
        )
        s = self._phone_re.sub(lambda m: self.mask_digits(m.group(0)), s)
        s = self._passport_re.sub(lambda m: self.mask_digits(m.group(0)), s)
        s = self._snils_re.sub(lambda m: self.mask_digits(m.group(0)), s)

        def fio_repl(m: re.Match) -> str:
            old = m.group(0)
            new = self.person_map.get(old)
            if new is None:
                base, variants = synth_person_fio(old)
                new = self.person_uniquer.claim(base, variants)
                self.person_map[old] = new
            parts = new.split()
            return f"{parts[0]} {parts[1][0]}. {parts[2][0]}." if len(parts) == 3 else new

        s = self._fio_re1.sub(fio_repl, s)
        s = self._fio_re2.sub(fio_repl, s)
        return s

    def mask_text(self, s: str) -> str:
        cached = self._text_cache.get(s)
        if cached is not None:
            return cached
        v = self._mask_text_impl(s)
        self._text_cache[s] = v
        return v

    def _mask_text_impl(self, s: str) -> str:
        self.stats["text_masked"] += 1
        toks = TOKEN_RE.findall(s)
        if toks:
            seen: set[str] = set()
            for t in toks:
                tl = t.lower()
                if tl in seen:
                    continue
                seen.add(tl)
                cands = self.exact_index.get(tl)
                if cands:
                    for real, repl in cands:
                        if real in s:
                            s = s.replace(real, repl)
            for t in set(toks):
                w = self.word_map.get(t.lower())
                if w and t in s:
                    s = s.replace(t, w)
        s = self._pii_sub(s)
        return s


# ----------------------------------------------------------------------------
# Проход 1: сбор значений для справочников
# ----------------------------------------------------------------------------

def _collect_attachment_vocab(text: str, vals: set, words: set) -> None:
    """Из вложения достаём значимые слова и значения атрибутов для словаря."""
    try:
        raw = base64.b64decode(text, validate=False)
    except Exception:
        return
    chunks: list[bytes] = []
    try:
        if raw[:2] == b"PK":
            with zipfile.ZipFile(io.BytesIO(raw)) as z:
                for name in z.namelist():
                    if name.lower().endswith((".xml", ".txt", ".rels", ".scrap")):
                        chunks.append(z.read(name))
        elif raw.lstrip()[:5] == b"<?xml" or raw[:3] == b"\xef\xbb\xbf":
            chunks.append(raw)
        else:
            return
    except Exception:
        return
    for d in chunks:
        s = d.decode("utf-8", errors="ignore")
        for a, v in ATTR_RE.findall(s):
            if a in DIAG_MASK_ATTRS and v.strip():
                vals.add(v.strip())
                for tok in TOKEN_RE.findall(v):
                    if len(tok) >= 4 and _has_cyr(tok):
                        words.add(tok)


def pass1(path: str, ps: Pseudonymizer) -> Counter:
    name_counts: Counter = Counter()
    name_cls: dict[str, str] = {}
    customer_names: set[str] = set()
    person_parts: dict[str, dict] = {}
    street_vals: set[str] = set()
    town_vals: set[str] = set()
    region_vals: set[str] = set()
    country_vals: set[str] = set()
    att_vals: set[str] = set()
    att_words: set[str] = set()

    for _, elem in etree.iterparse(path, events=("end",), huge_tree=True):
        par = elem.getparent()
        if par is None or par.tag != RDF_RDF:
            continue
        cls_tag = elem.tag
        cls = cls_tag.rsplit("}", 1)[-1] if isinstance(cls_tag, str) else ""
        cls_low = cls.lower()
        if cls_low in SKIP_TEXT_CLASSES:
            _cleanup(elem)
            continue
        about = elem.get(RDF_ABOUT)
        raw_about = about.lstrip("#_") if about else None

        for el in elem.iter():
            t = el.tag
            if not isinstance(t, str):
                continue
            txt = el.text
            if not txt or not txt.strip():
                continue
            s = txt.strip()
            local = t.rsplit("}", 1)[-1]
            last = local.rsplit(".", 1)[-1]
            last_low = last.lower()

            if local.startswith("StreetDetail.") and last_low == "name":
                street_vals.add(s)
            elif local == "TownDetail.name":
                town_vals.add(s)
            elif local == "TownDetail.stateOrProvince":
                region_vals.add(s)
            elif local == "TownDetail.country":
                country_vals.add(s)
            elif local.lower() in ATTACH_FIELDS:
                _collect_attachment_vocab(s, att_vals, att_words)
            elif cls_low in CUSTOMER_CLASSES and last_low == "name":
                customer_names.add(s)
            elif cls_low in PERSON_CLASSES:
                key = last_low
                if key in ("lastname", "firstname", "middlename", "name"):
                    d = person_parts.setdefault(raw_about or s, {})
                    d.setdefault(key, s)
            elif last_low in NAME_LAST:
                name_counts[s] += 1
                if s not in name_cls:
                    name_cls[s] = cls
        _cleanup(elem)

    # ---- построение справочников (биекция) ----
    for val, cls in name_cls.items():
        base, variants = make_object_name(val, cls)
        ps.name_map[val] = ps.name_uniquer.claim(base, variants)
    for val in customer_names:
        base, variants = synth_person_fio(val)
        ps.person_map[val] = ps.person_uniquer.claim(base, variants)
    for about in person_parts:
        # общий Uniquer с person_map: ФИО сотрудников и абонентов не совпадают
        base, variants = synth_person_fio("obj:" + about)
        full = ps.person_uniquer.claim(base, variants)
        parts_full = full.split()
        fam = parts_full[0]
        name = parts_full[1] if len(parts_full) > 1 else fam
        mid = parts_full[2] if len(parts_full) > 2 else ""
        ps.person_obj[about] = {
            "lastname": fam,
            "firstname": name,
            "middlename": mid,
            "name": full,
        }
    for val in street_vals:
        base, variants = synth_street(val)
        ps.street_map[val] = ps.addr_uniquer.claim(base, variants)
    for val in town_vals:
        base, variants = synth_town(val)
        ps.town_map[val] = ps.addr_uniquer.claim(base, variants)
    for val in region_vals:
        base, variants = synth_region(val)
        ps.region_map[val] = ps.addr_uniquer.claim(base, variants)
    for val in country_vals:
        base, variants = synth_country(val)
        ps.country_map[val] = ps.addr_uniquer.claim(base, variants)
    for val in att_vals:
        base, variants = make_object_name(val, "Attachment")
        ps.att_val_map[val] = ps.name_uniquer.claim(base, variants)
    ps.att_words = att_words

    ps.build_text_index(name_counts)
    ps.stats["name_distinct"] = len(ps.name_map)
    ps.stats["person_distinct"] = len(ps.person_map)
    ps.stats["street_distinct"] = len(ps.street_map)
    ps.stats["town_distinct"] = len(ps.town_map)
    ps.stats["att_distinct"] = len(ps.att_val_map)
    return name_counts


def _cleanup(elem) -> None:
    elem.clear()
    par = elem.getparent()
    while par is not None and elem.getprevious() is not None:
        del par[0]


# ----------------------------------------------------------------------------
# Вложения
# ----------------------------------------------------------------------------

def mask_xml_bytes(data: bytes, ps: Pseudonymizer) -> bytes:
    had_bom = data.startswith(b"\xef\xbb\xbf")
    if had_bom:
        data = data[3:]
    try:
        root = etree.fromstring(data)
    except etree.XMLSyntaxError:
        return b"\xef\xbb\xbf" + data if had_bom else data
    for el in root.iter():
        if not isinstance(el.tag, str):
            continue
        for a in list(el.attrib):
            al = a.rsplit("}", 1)[-1]
            v = el.attrib[a]
            vs = v.strip()
            if not vs:
                continue
            if UUID_RE.match(vs):
                # ссылки на объекты модели — тем же отображением, что и rdf:about:
                # связи диаграмм остаются валидными в анонимизированной модели
                el.attrib[a] = ps.map_uuid(vs.lstrip("#_"))
                continue
            if al in DIAG_MASK_ATTRS:
                nv = ps.mask_text(vs)
                if al in DIAG_DIGIT_ATTRS:
                    nv = ps.mask_digits(nv)
                el.attrib[a] = nv
        if el.text and el.text.strip():
            el.text = ps.mask_text(el.text.strip())
    out = etree.tostring(root, xml_declaration=True, encoding="UTF-8")
    return b"\xef\xbb\xbf" + out if had_bom else out


def mask_attachment_value(text: str, ps: Pseudonymizer) -> str:
    ps.stats["attachments_seen"] += 1
    try:
        raw = base64.b64decode(text, validate=False)
    except Exception:
        return text
    try:
        if raw[:2] == b"PK":
            src = io.BytesIO(raw)
            dst = io.BytesIO()
            with zipfile.ZipFile(src) as z, zipfile.ZipFile(dst, "w", zipfile.ZIP_DEFLATED) as zo:
                for name in z.namelist():
                    data = z.read(name)
                    if name.lower().endswith((".xml", ".txt", ".rels", ".scrap")):
                        data = mask_xml_bytes(data, ps)
                    zi = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
                    zi.compress_type = zipfile.ZIP_DEFLATED
                    zo.writestr(zi, data)
            new = dst.getvalue()
        elif raw.lstrip()[:5] == b"<?xml" or raw[:3] == b"\xef\xbb\xbf":
            new = mask_xml_bytes(raw, ps)
        else:
            return text  # PNG и прочие бинарные вложения не изменяем
        if new == raw:
            return text
        ps.stats["attachments_masked"] += 1
        return base64.b64encode(new).decode("ascii")
    except Exception:
        return text


# ----------------------------------------------------------------------------
# Проход 2: анонимизация + потоковая запись
# ----------------------------------------------------------------------------

def read_prolog(path: str, max_head: int = 8 * 1024 * 1024) -> tuple[bytes, list[bytes], bytes]:
    """XML-декларация, PI/комментарии до корня и открывающий тег корня (дословно)."""
    with open(path, "rb") as f:
        head = f.read(max_head)
    if head.startswith(b"\xef\xbb\xbf"):
        head = head[3:]
    m = re.match(rb"<\?xml[^>]*\?>", head)
    decl = m.group(0) if m else b'<?xml version="1.0" encoding="utf-8"?>'
    rest = head[m.end():] if m else head
    items: list[bytes] = []
    pos = 0
    root_open = b""
    while True:
        lt = rest.find(b"<", pos)
        if lt == -1:
            break
        if rest.startswith(b"<?", lt):
            end = rest.find(b"?>", lt + 2)
            if end == -1:
                break
            items.append(rest[lt:end + 2])
            pos = end + 2
        elif rest.startswith(b"<!--", lt):
            end = rest.find(b"-->", lt + 4)
            if end == -1:
                break
            items.append(rest[lt:end + 3])
            pos = end + 3
        else:
            # открывающий тег корня: ищем '>' вне кавычек
            i = lt + 1
            quote = None
            while i < len(rest):
                ch = rest[i:i + 1]
                if quote:
                    if ch == quote:
                        quote = None
                elif ch == b'"' or ch == b"'":
                    quote = ch
                elif ch == b">":
                    root_open = rest[lt:i + 1]
                    break
                i += 1
            break
    if not root_open:
        raise SystemExit("Не найден корневой элемент в начале файла")
    return decl, items, root_open


def make_ns_stripper(root_open: bytes):
    decls = re.findall(rb'xmlns:([A-Za-z_][\w.-]*)="([^"]*)"', root_open)
    if not decls:
        return None
    pairs = b"|".join(
        b"xmlns:" + re.escape(p) + b'="' + re.escape(u) + b'"' for p, u in decls
    )
    return re.compile(rb"\s+(?:" + pairs + b")")


def pass2(path: str, out_path: str, ps: Pseudonymizer, mask_coords: bool) -> None:
    decl, items, root_open = read_prolog(path)
    ns_sub = make_ns_stripper(root_open)

    with open(out_path, "wb", buffering=4 * 1024 * 1024) as out:
        out.write(decl + b"\n")
        for raw in items:
            out.write(raw + b"\n")
        out.write(root_open)

        for _, elem in etree.iterparse(path, events=("end",), huge_tree=True):
            par = elem.getparent()
            if par is None or par.tag != RDF_RDF:
                continue

            cls_tag = elem.tag
            cls = cls_tag.rsplit("}", 1)[-1] if isinstance(cls_tag, str) else ""
            cls_low = cls.lower()
            about = elem.get(RDF_ABOUT)
            if about:
                raw_about = about.lstrip("#_")
                elem.set(RDF_ABOUT, "#_" + ps.map_uuid(raw_about))
            else:
                raw_about = None

            if cls_low not in SKIP_TEXT_CLASSES:
                person_syn = ps.person_obj.get(raw_about) if cls_low in PERSON_CLASSES else None

                for el in elem.iter():
                    t = el.tag
                    if not isinstance(t, str):
                        continue
                    res = el.get(RDF_RESOURCE)
                    if res is not None and res[:1] == "#":
                        el.set(RDF_RESOURCE, "#_" + ps.map_uuid(res[1:].lstrip("#_")))
                        ps.stats["refs"] += 1

                    txt = el.text
                    if not txt or not txt.strip():
                        continue
                    s = txt.strip()
                    local = t.rsplit("}", 1)[-1]
                    local_low = local.lower()
                    last = local.rsplit(".", 1)[-1]
                    last_low = last.lower()

                    if last_low in ATTACH_FIELDS or local_low in ATTACH_FIELDS:
                        el.text = mask_attachment_value(s, ps)
                        continue

                    if local == "TownDetail.country":
                        el.text = ps.country_map.get(s) or ps.map_name(s)
                        ps.stats["addr"] += 1
                        continue

                    if local == "TownDetail.stateOrProvince":
                        el.text = ps.region_map.get(s) or ps.map_name(s)
                        ps.stats["addr"] += 1
                        continue

                    if local == "TownDetail.name":
                        el.text = ps.town_map.get(s) or ps.map_name(s)
                        ps.stats["addr"] += 1
                        continue

                    if local.startswith("StreetDetail.") and last_low == "name":
                        el.text = ps.street_map.get(s) or ps.map_name(s)
                        ps.stats["addr"] += 1
                        continue

                    if cls_low in PERSON_CLASSES and person_syn:
                        if last_low in ("lastname", "firstname", "middlename", "name"):
                            nv = person_syn.get(last_low)
                            if nv:
                                el.text = nv
                                ps.stats["person"] += 1
                            continue

                    if cls_low in CUSTOMER_CLASSES and last_low == "name":
                        el.text = ps.person_map.get(s) or ps.map_name(s)
                        ps.stats["person"] += 1
                        continue

                    if last_low in NAME_LAST:
                        el.text = ps.map_name(s)
                        ps.stats["names"] += 1
                        continue

                    if last_low in ID_LAST or local_low in ID_FULL:
                        if UUID_RE.match(s):
                            el.text = ps.map_uuid_value(s)
                        else:
                            el.text = ps.mask_digits(s)
                            ps.stats["ids"] += 1
                        continue

                    if last_low in FREE_LAST:
                        el.text = ps.mask_text(s)
                        continue

                    if mask_coords and last_low in ("xposition", "yposition"):
                        el.text = _map_coord(s, raw_about, ps)
                        continue

            buf = etree.tostring(elem, with_tail=True, encoding="utf-8",
                                 xml_declaration=False)
            if ns_sub is not None:
                buf = ns_sub.sub(b"", buf)
            out.write(buf)
            _cleanup(elem)

        out.write(b"\n</rdf:RDF>\n")


def _map_coord(s: str, raw_about: str | None, ps: Pseudonymizer) -> str:
    try:
        v = float(s)
    except ValueError:
        return s
    seed = raw_about or s
    h = int.from_bytes(_h("coord", seed, 8), "big")
    off = ((h % 100000) / 100000 - 0.5) * 0.1
    dec = len(s.split(".")[1]) if "." in s else 0
    return f"{v + off:.{dec}f}"


# ----------------------------------------------------------------------------
# main
# ----------------------------------------------------------------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="Потоковое обезличивание CIM RDF XML по ТЗ (детерминированное)"
    )
    ap.add_argument("--input", required=True, help="исходный XML")
    ap.add_argument("--output", required=True, help="куда писать результат")
    ap.add_argument(
        "--secret-file", default=None,
        help="файл ключа (по умолчанию <output>.anon_secret рядом с результатом)",
    )
    ap.add_argument(
        "--keep-coords", action="store_true",
        help="не маскировать координаты (по умолчанию сдвигаются, если есть)",
    )
    args = ap.parse_args()

    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    secret_file = Path(args.secret_file) if args.secret_file else \
        out_path.parent / (out_path.name + ".anon_secret")
    global KEY
    KEY = load_secret(secret_file)

    ps = Pseudonymizer()
    t0 = time.time()
    print("Проход 1: сбор справочников…")
    pass1(args.input, ps)
    t1 = time.time()
    print(f"  справочники: имён={ps.stats['name_distinct']}, ФИО={ps.stats['person_distinct']}, "
          f"улиц={ps.stats['street_distinct']}, городов={ps.stats['town_distinct']}, "
          f"из вложений={ps.stats['att_distinct']}, "
          f"коллизий разрешено={ps.name_uniquer.collisions + ps.person_uniquer.collisions + ps.addr_uniquer.collisions} "
          f"({t1 - t0:.1f} с)")
    print("Проход 2: обезличивание…")
    pass2(args.input, args.output, ps, mask_coords=not args.keep_coords)
    t2 = time.time()
    st = ps.stats
    print(f"  UUID заменено: {st['uuid']} | ссылок: {st['refs']} | "
          f"наименований: {st['names']} | ФИО: {st['person']} | адресов: {st['addr']} | "
          f"цифровых полей: {st['ids']} | текстов маскировано: {st['text_masked']} | "
          f"вложений: {st['attachments_masked']}/{st['attachments_seen']} ({t2 - t1:.1f} с)")
    print(f"Готово за {t2 - t0:.1f} с -> {out_path}")
    print(f"Размер: {out_path.stat().st_size:,} байт")


if __name__ == "__main__":
    main()

