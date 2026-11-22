from dataclasses import dataclass
from typing import Optional

@dataclass(frozen=True)
class ParsedItem:
    kind: str                 # source | config
    value: str
    protocol: Optional[str] = None
    host: Optional[str] = None
    port: Optional[int] = None
    note: str = ''
