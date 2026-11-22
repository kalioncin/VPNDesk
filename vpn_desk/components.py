"""Verified downloader for the official sing-box Windows command-line package.

The binary is installed as an optional local component. This module never starts a
proxy, VPN tunnel, service, TUN adapter, or changes Windows network settings.
"""
from __future__ import annotations

import hashlib
import json
import os
import platform
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse

API = 'https://api.github.com/repos/SagerNet/sing-box/releases/latest'
USER_AGENT = 'VPNDesk-component-manager/0.3'
MAX_DOWNLOAD = 100 * 1024 * 1024
MAX_UNPACKED = 250 * 1024 * 1024
MAX_ENTRIES = 300


def windows_architecture() -> str:
    machine = (os.environ.get('PROCESSOR_ARCHITEW6432') or
               os.environ.get('PROCESSOR_ARCHITECTURE') or platform.machine()).lower()
    if machine in {'arm64', 'aarch64'}:
        return 'arm64'
    if machine in {'amd64', 'x86_64', 'x64'}:
        return 'amd64'
    if machine in {'x86', 'i386', 'i686'}:
        return '386'
    raise RuntimeError(f'Неподдерживаемая архитектура Windows: {machine}')


def latest_singbox_release(timeout: int = 15) -> dict:
    request = urllib.request.Request(API, headers={'User-Agent': USER_AGENT,
        'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = json.loads(response.read(2 * 1024 * 1024))
    if data.get('prerelease') or data.get('draft'):
        raise RuntimeError('GitHub вернул не стабильный релиз sing-box')
    version = str(data.get('tag_name') or '').removeprefix('v')
    arch = windows_architecture()
    expected = f'sing-box-{version}-windows-{arch}.zip'
    asset = next((a for a in data.get('assets', []) if a.get('name') == expected), None)
    if not asset:
        raise RuntimeError(f'В официальном релизе нет архива {expected}')
    digest = asset.get('digest') or ''
    if not digest.startswith('sha256:') or len(digest) != 71:
        raise RuntimeError('У релизного архива нет опубликованного SHA-256 digest; установка заблокирована')
    return {'version': version, 'asset_name': expected,
            'url': asset.get('browser_download_url'), 'sha256': digest.split(':', 1)[1],
            'release_url': data.get('html_url')}


def _download(url: str, destination: Path, expected_sha256: str, timeout: int = 60):
    parsed=urlparse(url)
    if parsed.scheme!='https' or parsed.hostname not in {'github.com','release-assets.githubusercontent.com','objects.githubusercontent.com'}:
        raise RuntimeError('Разрешены только HTTPS-загрузки с доменов GitHub')
    request = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
    digest = hashlib.sha256(); size = 0
    with urllib.request.urlopen(request, timeout=timeout) as response, destination.open('wb') as out:
        final_host=urlparse(response.geturl()).hostname
        if urlparse(response.geturl()).scheme!='https' or final_host not in {'github.com','release-assets.githubusercontent.com','objects.githubusercontent.com'}:
            raise RuntimeError('GitHub перенаправил загрузку на неожиданный домен')
        length = int(response.headers.get('Content-Length') or 0)
        if length > MAX_DOWNLOAD:
            raise RuntimeError('Архив превышает лимит загрузки 100 МБ')
        while True:
            chunk = response.read(1024 * 1024)
            if not chunk: break
            size += len(chunk)
            if size > MAX_DOWNLOAD: raise RuntimeError('Загрузка превысила лимит 100 МБ')
            digest.update(chunk); out.write(chunk)
    actual = digest.hexdigest()
    if actual.lower() != expected_sha256.lower():
        raise RuntimeError('SHA-256 не совпал. Архив удалён, установка отменена.')
    return actual


def install_singbox(root: Path, release: dict) -> Path:
    root = Path(root); root.mkdir(parents=True, exist_ok=True)
    version_dir = root / f"sing-box-{release['version']}"
    if version_dir.exists():
        exe = version_dir / 'sing-box.exe'
        if exe.is_file():
            try:
                current=installed_version(exe)
                if os.name!='nt' or release['version'] in current:return exe
            except Exception:
                pass
        shutil.rmtree(version_dir, ignore_errors=True)
    with tempfile.TemporaryDirectory(prefix='vpndesk-singbox-') as tmp:
        tmp_path = Path(tmp); archive_path = tmp_path / 'sing-box.zip'
        _download(release['url'], archive_path, release['sha256'])
        stage = tmp_path / 'stage'; stage.mkdir()
        total = 0; entries = 0; found_exe = False
        with zipfile.ZipFile(archive_path) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_ENTRIES: raise RuntimeError('В архиве слишком много файлов')
            for info in infos:
                if info.is_dir(): continue
                name = info.filename.replace('\\', '/')
                rel = PurePosixPath(name)
                if rel.is_absolute() or any(part in {'..', ''} for part in rel.parts):
                    raise RuntimeError('Архив содержит небезопасный путь')
                total += info.file_size; entries += 1
                if total > MAX_UNPACKED: raise RuntimeError('Распакованный архив превышает лимит 250 МБ')
                if info.file_size and (info.compress_size == 0 or info.file_size/max(1,info.compress_size)>500):
                    raise RuntimeError('Подозрительный коэффициент сжатия в архиве')
                target = stage.joinpath(*rel.parts)
                target.parent.mkdir(parents=True, exist_ok=True)
                with zf.open(info) as src, target.open('wb') as dst:
                    shutil.copyfileobj(src, dst, 1024 * 1024)
                if rel.name.lower() == 'sing-box.exe': found_exe = True
        if not found_exe: raise RuntimeError('В официальном архиве не найден sing-box.exe')
        exe_candidates = list(stage.rglob('sing-box.exe'))
        if len(exe_candidates) != 1: raise RuntimeError('В архиве неоднозначный набор исполняемых файлов')
        # Flatten the official release folder into our versioned component directory.
        payload = exe_candidates[0].parent
        final_stage = tmp_path / 'final'; final_stage.mkdir()
        for child in payload.iterdir():
            if child.is_file(): shutil.copy2(child, final_stage / child.name)
        exe = final_stage / 'sing-box.exe'
        if os.name == 'nt':
            result = subprocess.run([str(exe), 'version'],capture_output=True,text=True,timeout=10,creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
            if result.returncode != 0: raise RuntimeError('Загруженный sing-box не прошёл проверку запуска')
        version_dir.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(final_stage), str(version_dir))
    return version_dir / 'sing-box.exe'


def installed_version(executable: Path) -> str:
    executable = Path(executable)
    if not executable.is_file(): return ''
    if os.name != 'nt': return 'установлен (проверка версии доступна только в Windows)'
    result = subprocess.run([str(executable), 'version'],capture_output=True,text=True,timeout=10,
                            creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    if result.returncode: raise RuntimeError(result.stderr[:300] or 'sing-box завершился с ошибкой')
    return (result.stdout or result.stderr).strip()[:200]
