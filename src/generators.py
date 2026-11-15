# src/generators.py
import hmac
import hashlib
import os

SECRET = os.environ["ANON_SECRET"].encode("utf-8")


def _hmac_hex(*parts: str) -> str:
    return hmac.new(SECRET, "|".join(parts).encode("utf-8"), hashlib.sha256).hexdigest()


def new_uuid(old_uuid: str) -> str:
    """Детерминированно превращает старый UUID в новый UUID-формат."""
    h = _hmac_hex("uuid", old_uuid)
    # 32 hex → 8-4-4-4-12
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def new_id(old_id: str) -> str:
    """old_id — это UUID без '#_' (мы её уже отрезали в parser)."""
    return "_" + new_uuid(old_id.lstrip("_"))


# ---- словари ----
PEOPLE = [
    "Иванов Иван Иванович",
    "Петров Пётр Петрович",
    "Сидоров Сидор Сидорович",
    "Кузнецов Алексей Николаевич",
    "Смирнова Анна Сергеевна",
    # ...минимум 200–500 записей
]

FRUIT_VEG_ADJ = [
    "Яблочный", "Грушевый", "Сливовый", "Вишнёвый", "Абрикосовый",
    "Персиковый", "Виноградный", "Арбузный", "Дынный", "Ананасовый",
    "Манговый", "Кивийный", "Лимонный", "Апельсиновый", "Мандариновый",
    "Банановый", "Гранитовый", "Оливковый", "Картофельный", "Морковный",
    "Свекольный", "Тыквенный", "Огуречный", "Томатный", "Капустный",
    "Луковый", "Чесночный", "Редисочный", "Гороховый", "Фасолевый",
    "Кукурузный", "Пшеничный", "Ржаной", "Овсяный", "Ячменный",
    "Рисовый", "Гречишный", "Просовый", "Кунжутный", "Арахисовый",
    # ... всего 60–80, чтобы коллизий было мало
]


def _pick(seq, *parts):
    return seq[int(_hmac_hex(*parts), 16) % len(seq)]


def new_object_name(old_name: str, class_label: str) -> str:
    """
    class_label — 'ПС', 'ТП', 'ЛЭП', 'РП', 'Substation' и т.п.
    Старое имя в хэш не входит как выборка, но входит в ключ → разные объекты
    с одинаковым именем получат разные новые имена (это нормально).
    """
    adj = _pick(FRUIT_VEG_ADJ, "obj-adj", old_name, class_label)
    suffix = _hmac_hex("obj-sfx", old_name)[:6].upper()
    return f"{adj} {class_label}-{suffix}"


def new_person_fio(old_fio: str) -> dict[str, str]:
    fio = _pick(PEOPLE, "person", old_fio)
    last, first, middle = fio.split()
    sfx = _hmac_hex("person-sfx", old_fio)[:6]
    return {
        "fio": fio,
        "email": f"{first.lower()}.{last.lower()}.{sfx}@example.test",
        "street": f"ул. {last}а",
    }


def new_number_string(old: str, salt: str) -> str:
    """Замена числового идентификатора той же длины (ИНН, КПП, табельный...)."""
    n = len(old)
    if n == 0:
        return old
    v = int(_hmac_hex(salt, old), 16) % (10 ** n)
    return str(v).zfill(n)