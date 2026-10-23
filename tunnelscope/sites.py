"""Validated user-managed domain lists. No URL fetches or IP-wide blocking."""
import urllib.parse
from .adult import hostname, CID

MAX_DOMAINS=100
MAX_TOTAL=2000

def normalize_site(value):
    if not isinstance(value,str) or not value.strip() or len(value)>2048:raise ValueError('Укажите домен или HTTPS-ссылку')
    value=value.strip()
    if any(x.isspace() for x in value) or '*' in value or '\\' in value:raise ValueError('Пробелы и маски в домене не допускаются')
    if '://' in value:
        try:
            url=urllib.parse.urlsplit(value)
            if url.scheme not in ('http','https') or url.username is not None or url.password is not None:raise ValueError()
            value=url.hostname or ''
            if url.port is not None and not 1<=url.port<=65535:raise ValueError()
        except ValueError:raise ValueError('Некорректная ссылка') from None
    try:value=value.rstrip('.').encode('idna').decode('ascii').lower()
    except UnicodeError:raise ValueError('Некорректный домен') from None
    name=hostname(value)
    if not name:raise ValueError('Нужен домен сайта, например example.com; IP и маски не поддерживаются')
    return name

def normalize_domains(values):
    if not isinstance(values,list) or len(values)>MAX_DOMAINS:raise ValueError('Не более 100 сайтов в одном списке')
    return sorted({normalize_site(v) for v in values})

def match_domain(name,domains):
    parts=name.split('.')
    return any('.'.join(parts[i:]) in domains for i in range(len(parts)-1))
