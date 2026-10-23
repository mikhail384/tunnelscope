"""Bounded TXT and Word domain import. Uploaded files are never saved or executed."""
import base64
import binascii
import io
import pathlib
import re
import xml.etree.ElementTree as ET
import zipfile
from .sites import MAX_DOMAINS, normalize_site

MAX_FILE = 512 * 1024
MAX_BODY = ((MAX_FILE + 2) // 3) * 4 + 4096
MAX_XML = 2 * 1024 * 1024
W = '{http://schemas.openxmlformats.org/wordprocessingml/2006/main}'


def word_text(raw):
    try:
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            entries = archive.infolist()
            if len(entries) > 256 or sum(e.file_size for e in entries) > 8 * 1024 * 1024:
                raise ValueError('Документ слишком большой после распаковки')
            docs = [e for e in entries if e.filename == 'word/document.xml']
            if len(docs) != 1 or docs[0].flag_bits & 1 or docs[0].file_size > MAX_XML:
                raise ValueError('Нужен обычный незашифрованный файл Word .docx')
            with archive.open(docs[0]) as f:
                xml = f.read(MAX_XML + 1)
        check=xml.decode('utf-16') if xml.startswith((b'\xff\xfe',b'\xfe\xff')) else xml.decode('utf-8-sig')
        if len(xml) > MAX_XML or '<!DOCTYPE' in check.upper() or '<!ENTITY' in check.upper():
            raise ValueError('Недопустимое содержимое Word')
        parts = []; depth = 0; count = 0
        for event, element in ET.iterparse(io.BytesIO(xml), events=('start', 'end')):
            if event == 'start':
                depth += 1; count += 1
                if depth > 64 or count > 30000:
                    raise ValueError('Слишком сложный документ Word')
            else:
                if element.tag == W + 't': parts.append(element.text or '')
                elif element.tag in (W + 'p', W + 'br', W + 'cr'): parts.append('\n')
                elif element.tag == W + 'tab': parts.append(' ')
                element.clear(); depth -= 1
        return ''.join(parts)
    except (zipfile.BadZipFile, KeyError, RuntimeError, OSError, NotImplementedError, UnicodeError, ET.ParseError):
        raise ValueError('Не удалось прочитать Word. Сохраните документ как .docx или .txt') from None


def plain_text(raw):
    if raw.startswith((b'\xff\xfe', b'\xfe\xff')):
        try: return raw.decode('utf-16')
        except UnicodeError: raise ValueError('Повреждённый текстовый файл') from None
    if b'\x00' in raw: raise ValueError('Нужен текстовый файл или Word .docx')
    for encoding in ('utf-8-sig', 'cp1251'):
        try: return raw.decode(encoding)
        except UnicodeError: pass
    raise ValueError('Не удалось определить кодировку текста')


def parse_file(filename, raw):
    if not isinstance(filename, str) or not 1 <= len(filename) <= 255:
        raise ValueError('Некорректное имя файла')
    suffix = pathlib.PurePath(filename).suffix.lower()
    if suffix not in ('.txt', '.docx', '.docs'):
        raise ValueError('Поддерживаются TXT и Word DOCX. Старый .doc сохраните как .docx')
    if not raw or len(raw) > MAX_FILE: raise ValueError('Файл должен быть непустым и не больше 512 КБ')
    text = word_text(raw) if suffix == '.docx' or suffix == '.docs' and raw.startswith(b'PK') else plain_text(raw)
    domains = set(); skipped = []; skipped_count = 0; valid_count = 0; tokens = 0
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith(('#', '//', ';')): continue
        line = line.split('#', 1)[0].strip()
        values = re.split(r'[\s,;]+', line)
        if values and values[0] in ('0.0.0.0', '127.0.0.1', '::', '::1'): values = values[1:]
        for value in values:
            if not value: continue
            tokens += 1
            if tokens > 20000: raise ValueError('Слишком много записей в файле')
            try: name = normalize_site(value)
            except ValueError:
                skipped_count += 1
                if len(skipped) < 5: skipped.append(value[:100])
                continue
            domains.add(name); valid_count += 1
            if len(domains) > MAX_DOMAINS:
                raise ValueError('В файле больше 100 разных доменов. Разделите список на несколько файлов')
    if not domains: raise ValueError('В файле не найдено допустимых доменов')
    return {'domains': sorted(domains), 'skipped': skipped_count, 'skipped_examples': skipped,
            'duplicates': valid_count - len(domains), 'format': 'Word' if suffix == '.docx' or suffix == '.docs' and raw.startswith(b'PK') else 'TXT'}


def decode_upload(body):
    if set(body) != {'filename', 'data'} or not isinstance(body['data'], str) or len(body['data']) > MAX_BODY - 4096:
        raise ValueError('Некорректный файл или размер больше 512 КБ')
    try: raw = base64.b64decode(body['data'], validate=True)
    except (binascii.Error, ValueError): raise ValueError('Повреждённые данные файла') from None
    return parse_file(body['filename'], raw)
