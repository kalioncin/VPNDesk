from __future__ import annotations
import hashlib, io, zipfile
from pathlib import Path
from .parser import parse_bytes, parse_text, parse_stream

SUPPORTED={'.txt','.json','.yaml','.yml','.csv','.conf','.list'}
MAX_ARCHIVE_ENTRIES=5000
MAX_COMPRESSION_RATIO=500

def read_file(path: Path, max_mb=512, max_unpacked_mb=1024):
    path=Path(path)
    limit=max_mb*1024*1024
    if path.stat().st_size > limit: raise ValueError(f'Файл больше лимита {max_mb} МБ')
    if path.suffix.lower()=='.zip':
        digest=hashlib.sha256()
        with path.open('rb') as archive_stream:
            while True:
                chunk=archive_stream.read(1024*1024)
                if not chunk: break
                digest.update(chunk)
        items=[]; errors=[]; total=0
        try:
            with zipfile.ZipFile(path) as zf:
                entries=zf.infolist()
                if len(entries)>MAX_ARCHIVE_ENTRIES:
                    raise ValueError(f'В архиве слишком много элементов: {len(entries)} (лимит {MAX_ARCHIVE_ENTRIES})')
                for info in entries:
                    if info.is_dir(): continue
                    if info.flag_bits & 0x1: errors.append((info.filename,'Зашифрованный архивный элемент пропущен')); continue
                    suffix=Path(info.filename).suffix.lower()
                    if suffix=='.zip':
                        errors.append((info.filename,'Вложенные ZIP-архивы не открываются автоматически')); continue
                    if suffix not in SUPPORTED: continue
                    if info.file_size and (info.compress_size==0 or info.file_size/max(1,info.compress_size)>MAX_COMPRESSION_RATIO):
                        errors.append((info.filename,'Подозрительный коэффициент сжатия; элемент пропущен')); continue
                    total += info.file_size
                    if total > max_unpacked_mb*1024*1024:
                        errors.append((info.filename,'Превышен лимит суммарного размера распаковки')); break
                    if info.file_size > max_mb*1024*1024:
                        errors.append((info.filename,'Слишком большой элемент')); continue
                    try:
                        with zf.open(info,'r') as member:
                            parsed, bad=parse_stream(member)
                        items.extend(parsed); errors.extend(bad)
                    except (OSError,RuntimeError,zipfile.BadZipFile) as exc:
                        errors.append((info.filename,f'Ошибка чтения: {exc}'))
        except zipfile.BadZipFile as exc: raise ValueError(f'Повреждённый ZIP: {exc}') from exc
        return items,errors,digest.hexdigest()
    if path.suffix.lower() not in SUPPORTED:
        raise ValueError('Формат файла не поддерживается')
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        # Hash in chunks, then parse the file incrementally without loading it all into RAM.
        while True:
            chunk=stream.read(1024*1024)
            if not chunk: break
            digest.update(chunk)
        stream.seek(0)
        items,errors=parse_stream(stream)
    return items,errors,digest.hexdigest()

def read_pasted(text):
    return parse_text(text)
