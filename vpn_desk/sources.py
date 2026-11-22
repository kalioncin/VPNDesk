from __future__ import annotations
import urllib.request, urllib.error
from .parser import parse_bytes

class SourceError(Exception):
    def __init__(self, message, code=None): self.code=code; super().__init__(message)

def fetch_source(url, timeout=12, max_mb=32):
    if not url.lower().startswith(('http://','https://')): raise SourceError('Разрешены только HTTP(S) источники')
    req=urllib.request.Request(url,headers={'User-Agent':'VPNDesk/0.2 (+local config inventory)'})
    try:
        with urllib.request.urlopen(req,timeout=timeout) as response:
            data=response.read(max_mb*1024*1024+1)
            if len(data)>max_mb*1024*1024: raise SourceError(f'Источник превышает лимит {max_mb} МБ')
            return parse_bytes(data,url)
    except urllib.error.HTTPError as exc:
        raise SourceError(f'HTTP {exc.code}',exc.code) from exc
    except (urllib.error.URLError,TimeoutError,OSError) as exc:
        raise SourceError(str(exc)) from exc
