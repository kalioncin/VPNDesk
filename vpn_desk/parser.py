"""Conservative parser for common proxy/VPN URI formats. Never connects."""
from __future__ import annotations
import base64, binascii, json, re
from urllib.parse import urlsplit, unquote
from .models import ParsedItem

SCHEMES = {'vless', 'vmess', 'trojan', 'ss', 'hysteria2', 'hy2', 'tuic'}
URI_RE = re.compile(r'(?i)(?:vless|vmess|trojan|ss|hysteria2|hy2|tuic)://[^\s<>"\']+')
URL_RE = re.compile(r'https?://[^\s<>"\']+', re.I)
MAX_TOKEN_LENGTH = 16384


def _clean_token(token: str) -> str:
    return token.strip().strip('"\'<>[]{}(),;')


def _vmess_details(value: str):
    payload = value.split('://', 1)[1].split('#', 1)[0]
    payload += '=' * (-len(payload) % 4)
    try:
        obj = json.loads(base64.urlsafe_b64decode(payload.encode()).decode('utf-8-sig'))
        host = str(obj.get('add') or '')
        port = int(obj.get('port') or 0)
        if host and 1 <= port <= 65535:
            return host, port
    except (ValueError, TypeError, UnicodeDecodeError, binascii.Error, json.JSONDecodeError):
        pass
    return None, None


def parse_config(value: str) -> ParsedItem:
    value = _clean_token(value)
    scheme = value.split('://', 1)[0].lower() if '://' in value else ''
    if scheme not in SCHEMES:
        raise ValueError('Неизвестный протокол')
    if scheme == 'vmess':
        host, port = _vmess_details(value)
        if not host or not port:
            raise ValueError('Некорректный VMess JSON/Base64')
        return ParsedItem('config', value, 'vmess', host, port)
    normalized = 'hysteria2' if scheme == 'hy2' else scheme
    try:
        parsed = urlsplit(value)
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f'Некорректный адрес или порт: {exc}') from exc
    if not host:
        raise ValueError('Не найден адрес сервера')
    if port is None:
        # Some URI formats allow a default port; we intentionally do not guess.
        raise ValueError('Не указан порт сервера')
    if not 1 <= port <= 65535:
        raise ValueError('Порт должен быть от 1 до 65535')
    return ParsedItem('config', value, normalized, host, port)


def parse_text(text: str) -> tuple[list[ParsedItem], list[tuple[str, str]]]:
    """Extract links regardless of line layout; report uncertain tokens, don't rewrite them."""
    found: list[ParsedItem] = []
    errors: list[tuple[str, str]] = []
    seen: set[str] = set()
    # URI regex catches several links on one line and links in column-oriented dumps.
    for match in URI_RE.finditer(text):
        raw = _clean_token(match.group(0))
        if raw in seen:
            continue
        seen.add(raw)
        if len(raw) > MAX_TOKEN_LENGTH:
            errors.append((raw[:180], 'Слишком длинная запись; пропущена для защиты памяти'))
            continue
        try:
            found.append(parse_config(raw))
        except ValueError as exc:
            errors.append((raw[:180], str(exc)))
    # Web URLs that are not config links are source candidates.
    for match in URL_RE.finditer(text):
        raw = _clean_token(match.group(0))
        if raw in seen:
            continue
        seen.add(raw)
        if len(raw) > MAX_TOKEN_LENGTH:
            errors.append((raw[:180], 'Слишком длинный URL; пропущен для защиты памяти'))
            continue
        found.append(ParsedItem('source', raw, note='URL-источник; содержимое ещё не загружено'))
    return found, errors


def parse_bytes(data: bytes, filename: str = '') -> tuple[list[ParsedItem], list[tuple[str, str]]]:
    # Try UTF-8 first, then common Windows encodings. Keep original bytes untouched.
    text = None
    for encoding in ('utf-8-sig', 'utf-16', 'cp1251', 'latin-1'):
        try:
            text = data.decode(encoding)
            break
        except UnicodeDecodeError:
            continue
    if text is None:
        return [], [(filename or 'Файл', 'Не удалось определить кодировку')]
    # Support base64-encoded subscription bodies only when decoding is clearly textual.
    stripped = ''.join(text.split())
    if len(stripped) > 80 and re.fullmatch(r'[A-Za-z0-9+/=_-]+', stripped):
        try:
            decoded = base64.urlsafe_b64decode(stripped + '=' * (-len(stripped) % 4))
            candidate = decoded.decode('utf-8')
            if URI_RE.search(candidate) or URL_RE.search(candidate):
                text = candidate
        except (ValueError, UnicodeDecodeError, binascii.Error):
            pass
    return parse_text(text)


def parse_stream(stream, chunk_size=1024*1024):
    """Incrementally scan a large stream with a bounded text buffer; results are retained for preview."""
    import codecs
    prefix = stream.read(4100)
    if prefix.startswith((b'\xff\xfe',b'\xfe\xff')):
        encoding='utf-16'
    elif prefix.count(b'\x00') > max(8,len(prefix)//5):
        encoding='utf-16-le' if prefix[1:2]==b'\x00' else 'utf-16-be'
    else:
        encoding='utf-8-sig'
        try: prefix.decode('utf-8-sig')
        except UnicodeDecodeError:
            try: prefix.decode('cp1251'); encoding='cp1251'
            except UnicodeDecodeError: encoding='latin-1'
    decoder = codecs.getincrementaldecoder(encoding)(errors='replace')
    buffer = decoder.decode(prefix)
    items=[]; errors=[]; seen=set()
    def consume(text):
        parsed,bad=parse_text(text)
        for item in parsed:
            key=(item.kind,item.value)
            if key not in seen:
                seen.add(key); items.append(item)
        errors.extend(bad)
    # Keep a generous tail so a URI split across read boundaries is not truncated.
    carry=65536
    while True:
        chunk=stream.read(chunk_size)
        if not chunk: break
        buffer += decoder.decode(chunk)
        if len(buffer)>carry*2:
            cutoff=len(buffer)-carry
            # If a token crosses the cutoff, preserve it in the next buffer.
            for rx in (URI_RE,URL_RE):
                for m in rx.finditer(buffer):
                    if m.start()<cutoff<m.end() and (m.end()-m.start())<=carry: cutoff=min(cutoff,m.start())
            consume(buffer[:cutoff])
            buffer=buffer[cutoff:]
    buffer += decoder.decode(b'',final=True)
    consume(buffer)
    return items,errors
