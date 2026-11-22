"""Bounded endpoint checks. No VPN tunnel or OS route/DNS changes are performed."""
from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor, wait, FIRST_COMPLETED
from threading import Event
from typing import Callable, Iterable


class CheckCancelled(Exception):
    def __init__(self, message, results=None):
        super().__init__(message)
        self.results = list(results or [])


def check_tcp(host: str, port: int, timeout: float = 4.0):
    started = time.perf_counter()
    try:
        with socket.create_connection((host, int(port)), timeout=max(0.2, float(timeout))):
            return 'reachable', round((time.perf_counter() - started) * 1000, 1), ''
    except (OSError, TimeoutError, ValueError) as exc:
        return 'unreachable', None, str(exc)[:250]


def classify_transport(protocol: str) -> str:
    return 'UDP' if str(protocol).lower() in {'hysteria2', 'hy2', 'tuic'} else 'TCP'


def run_tcp_checks(records: Iterable, *, timeout: float = 4.0, max_workers: int = 16,
                   cancel_event: Event | None = None, pause_event: Event | None = None,
                   progress: Callable[[int, int, dict], None] | None = None):
    """Run a bounded number of TCP probes and return (id,status,latency,error) tuples.

    At most 2*workers futures are queued at once, allowing cancellation and avoiding
    a giant future list when the catalogue contains many thousands of records.
    """
    rows = list(records)
    total = len(rows)
    if not total:
        return []
    workers = max(1, min(int(max_workers), 128, total))
    pending_limit = max(workers, workers * 2)
    iterator = iter(rows)
    results = []
    completed = 0
    pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix='VPNDeskCheck')
    pending = {}
    def submit_next():
        try:
            row = next(iterator)
        except StopIteration:
            return False
        future = pool.submit(check_tcp, row['host'], row['port'], timeout)
        pending[future] = row['id']
        return True
    try:
        for _ in range(min(pending_limit, total)):
            submit_next()
        while pending:
            while pause_event and pause_event.is_set():
                if cancel_event and cancel_event.is_set():
                    raise CheckCancelled('Проверка отменена пользователем', results)
                time.sleep(0.1)
            if cancel_event and cancel_event.is_set():
                raise CheckCancelled('Проверка отменена пользователем', results)
            done, _ = wait(tuple(pending), timeout=0.2, return_when=FIRST_COMPLETED)
            if not done:
                continue
            for future in done:
                config_id = pending.pop(future)
                try:
                    status, latency, error = future.result()
                except Exception as exc:
                    status, latency, error = 'unreachable', None, str(exc)[:250]
                results.append((config_id, status, latency, error))
                completed += 1
                if progress:
                    progress(completed, total, results[-1])
                if cancel_event and cancel_event.is_set():
                    raise CheckCancelled('Проверка отменена пользователем', results)
                submit_next()
    except CheckCancelled:
        for future in pending:
            future.cancel()
        pool.shutdown(wait=False, cancel_futures=True)
        raise
    else:
        pool.shutdown(wait=True)
    return results

# --- Isolated protocol-level checks through sing-box (no Windows TUN/routes/DNS changes) ---
import base64
import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit, parse_qs, unquote


def _query(uri):
    return {k: (v[-1] if v else '') for k, v in parse_qs(urlsplit(uri).query, keep_blank_values=True).items()}


def _tls_options(q, default_sni=''):
    tls={'enabled': True}
    server_name=q.get('sni') or q.get('peer') or default_sni
    if server_name: tls['server_name']=server_name
    if q.get('fp'):
        tls['utls']={'enabled': True, 'fingerprint': q['fp']}
    if q.get('security')=='reality' or q.get('pbk'):
        if not q.get('pbk'):
            raise ValueError('Для Reality не указан публичный ключ pbk')
        reality={'enabled': True, 'public_key': q['pbk']}
        if q.get('sid'): reality['short_id']=q['sid']
        tls['reality']=reality
    if q.get('allowInsecure')=='1' or q.get('insecure')=='1':
        # Explicitly honor only a URI flag supplied by the user.
        tls['insecure']=True
    return tls


def _transport_options(q):
    kind=(q.get('type') or q.get('network') or '').lower()
    if kind in ('ws','websocket'):
        path=q.get('path') or '/'
        headers={}
        host=q.get('host') or q.get('authority')
        if host: headers['Host']=host
        return {'type':'ws','path':path,'headers':headers}
    if kind in ('grpc','gun'):
        name=q.get('serviceName') or q.get('service_name') or ''
        result={'type':'grpc'}
        if name: result['service_name']=name
        return result
    if kind in ('httpupgrade','http-upgrade'):
        return {'type':'httpupgrade','path':q.get('path') or '/', 'host':q.get('host') or ''}
    if kind in ('http','h2'):
        return {'type':'http','host':[x for x in (q.get('host') or '').split(',') if x], 'path':q.get('path') or '/'}
    if kind in ('tcp','raw',''):
        return None
    raise ValueError(f'Транспорт {kind} пока не поддерживается полной проверкой')


def build_singbox_outbound(uri: str) -> dict:
    """Convert common share URIs to a minimal sing-box outbound; unsupported extras fail closed."""
    parsed=urlsplit(uri.strip())
    scheme=parsed.scheme.lower()
    q=_query(uri)
    host=parsed.hostname
    port=parsed.port
    if scheme=='vmess':
        payload=uri.split('://',1)[1].split('#',1)[0]
        payload += '=' * (-len(payload)%4)
        obj=json.loads(base64.urlsafe_b64decode(payload.encode()).decode('utf-8-sig'))
        host=str(obj.get('add') or '')
        port=int(obj.get('port') or 0)
        outbound={'type':'vmess','tag':'proxy','server':host,'server_port':port,
                  'uuid':str(obj.get('id') or ''),'security':str(obj.get('scy') or 'auto'),
                  'alter_id':int(obj.get('aid') or 0)}
        if str(obj.get('tls') or '').lower() in ('tls','true','1'):
            tls={'enabled':True}
            if obj.get('sni'): tls['server_name']=str(obj['sni'])
            outbound['tls']=tls
        net=str(obj.get('net') or 'tcp').lower()
        if net=='ws':
            headers={}
            if obj.get('host'): headers['Host']=str(obj['host'])
            outbound['transport']={'type':'ws','path':str(obj.get('path') or '/'),'headers':headers}
        elif net=='grpc':
            outbound['transport']={'type':'grpc','service_name':str(obj.get('path') or '')}
        elif net=='http':
            outbound['transport']={'type':'http','host':[str(obj.get('host'))] if obj.get('host') else [],'path':str(obj.get('path') or '/')}
        elif net!='tcp':
            raise ValueError(f'Транспорт VMess {net} пока не поддерживается')
    elif scheme in ('vless','trojan','ss','hysteria2','hy2','tuic'):
        if not host or not port: raise ValueError('В URI отсутствует сервер или порт')
        outbound={'type':'hysteria2' if scheme=='hy2' else scheme,'tag':'proxy','server':host,'server_port':port}
        user=unquote(parsed.username or '')
        password=unquote(parsed.password or '')
        if scheme=='vless':
            outbound['uuid']=user
            if q.get('flow'): outbound['flow']=q['flow']
            if q.get('security','tls')!='none': outbound['tls']=_tls_options(q,host)
            transport=_transport_options(q)
            if transport: outbound['transport']=transport
        elif scheme=='trojan':
            outbound['password']=user
            outbound['tls']=_tls_options(q,host)
            transport=_transport_options(q)
            if transport: outbound['transport']=transport
        elif scheme=='ss':
            method=user; secret=password
            if not secret and user:
                try:
                    decoded=base64.urlsafe_b64decode(user+'='*(-len(user)%4)).decode('utf-8')
                    if ':' in decoded: method,secret=decoded.split(':',1)
                except Exception: pass
            if not secret and '@' not in parsed.netloc:
                raw=parsed.netloc.split('#',1)[0]
                decoded=base64.urlsafe_b64decode(raw+'='*(-len(raw)%4)).decode('utf-8')
                method,secret=decoded.split(':',1)
            if not method or not secret: raise ValueError('Не удалось разобрать метод и пароль Shadowsocks')
            outbound.update(method=method,password=secret)
            if q.get('plugin'): raise ValueError('Shadowsocks plugin пока не поддерживается полной проверкой')
        elif scheme in ('hysteria2','hy2'):
            outbound['password']=user or password
            outbound['tls']=_tls_options(q,host)
            if q.get('obfs'):
                outbound['obfs']={'type':q['obfs'],'password':q.get('obfs-password','')}
        elif scheme=='tuic':
            outbound.update(uuid=user,password=password,congestion_control=q.get('congestion_control','bbr'),
                            udp_relay_mode=q.get('udp_relay_mode','native'))
            outbound['tls']=_tls_options(q,host)
    else:
        raise ValueError(f'Протокол {scheme or "неизвестен"} не поддерживается')
    if not outbound.get('server') or not (1 <= int(outbound.get('server_port') or 0) <= 65535):
        raise ValueError('Некорректный сервер/порт в URI')
    if scheme in ('vless','vmess') and not outbound.get('uuid'):
        raise ValueError('В конфигурации отсутствует UUID')
    return outbound


def _socks5_connect(proxy_port, host='www.gstatic.com', port=443, timeout=8.0):
    sock=socket.create_connection(('127.0.0.1', proxy_port), timeout=timeout)
    sock.settimeout(timeout)
    sock.sendall(b'\x05\x01\x00')
    if sock.recv(2)!=b'\x05\x00':
        sock.close(); raise OSError('Локальный SOCKS5 не принял метод без авторизации')
    name=host.encode('idna')
    sock.sendall(b'\x05\x01\x00\x03'+bytes([len(name)])+name+int(port).to_bytes(2,'big'))
    head=sock.recv(4)
    if len(head)!=4 or head[1]!=0:
        sock.close(); raise OSError(f'SOCKS5 CONNECT отклонён: {head!r}')
    atyp=head[3]
    if atyp==1: sock.recv(4)
    elif atyp==3:
        n=sock.recv(1)
        if n: sock.recv(n[0])
    elif atyp==4: sock.recv(16)
    sock.recv(2)
    return sock


def check_singbox(uri: str, binary: str, timeout: float=10.0, cancel_event: Event | None=None):
    """Start one isolated sing-box process and verify a real HTTPS response via its proxy."""
    started=time.perf_counter(); process=None; temp_dir=None
    try:
        outbound=build_singbox_outbound(uri)
        with socket.socket() as probe:
            probe.bind(('127.0.0.1',0)); socks_port=probe.getsockname()[1]
        config={'log':{'level':'error'},
                'inbounds':[{'type':'socks','tag':'local-in','listen':'127.0.0.1','listen_port':socks_port}],
                'outbounds':[outbound,{'type':'direct','tag':'direct'}],
                'route':{'final':'proxy'}}
        temp_dir=tempfile.TemporaryDirectory(prefix='vpndesk-check-')
        config_path=Path(temp_dir.name)/'config.json'
        config_path.write_text(json.dumps(config,ensure_ascii=False),encoding='utf-8')
        check=subprocess.run([binary,'check','-c',str(config_path)],capture_output=True,text=True,timeout=max(3,timeout),creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        if check.returncode:
            detail=(check.stderr or check.stdout or 'sing-box отклонил конфигурацию').strip()[-500:]
            return 'unreachable',None,'Ошибка проверки sing-box: '+detail
        process=subprocess.Popen([binary,'run','-c',str(config_path)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,
                                 creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
        deadline=time.monotonic()+min(8.0,max(2.0,timeout/2))
        sock=None
        while time.monotonic()<deadline:
            if cancel_event and cancel_event.is_set(): return 'unreachable',None,'Проверка отменена пользователем'
            if process.poll() is not None:
                err=process.stderr.read(1200).decode('utf-8','replace') if process.stderr else ''
                return 'unreachable',None,'sing-box завершился: '+err[-400:]
            try:
                sock=_socks5_connect(socks_port,timeout=1.0); break
            except OSError: time.sleep(0.15)
        if sock is None: return 'unreachable',None,'Локальный SOCKS5 sing-box не запустился'
        context=ssl.create_default_context()
        with context.wrap_socket(sock,server_hostname='www.gstatic.com') as tls:
            tls.sendall(b'GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\nUser-Agent: VPNDesk-check/1.0\r\n\r\n')
            response=tls.recv(512)
        first=response.split(b'\r\n',1)[0].decode('ascii','replace')
        if b' 204 ' not in response.split(b'\r\n',1)[0] and b' 200 ' not in response.split(b'\r\n',1)[0]:
            return 'unreachable',None,'Через конфигурацию получен неожиданный HTTPS-ответ: '+first[:180]
        return 'reachable',round((time.perf_counter()-started)*1000,1),'Протокольный выход подтверждён: '+first[:100]
    except subprocess.TimeoutExpired:
        return 'unreachable',None,'Тайм-аут sing-box/HTTPS-теста'
    except Exception as exc:
        return 'unreachable',None,f'{type(exc).__name__}: {str(exc)[:220]}'
    finally:
        if process is not None:
            try: process.terminate(); process.wait(timeout=1.5)
            except Exception:
                try: process.kill()
                except Exception: pass
        if temp_dir is not None: temp_dir.cleanup()


def run_singbox_checks(records, binary, *, timeout=10.0, max_workers=4,
                       cancel_event: Event | None=None, pause_event: Event | None=None,
                       progress: Callable[[int,int,dict],None] | None=None):
    rows=list(records); total=len(rows)
    if not total: return []
    workers=max(1,min(int(max_workers),8,total)); iterator=iter(rows); pending={}; results=[]; completed=0
    pool=ThreadPoolExecutor(max_workers=workers,thread_name_prefix='VPNDeskProtocol')
    def submit_one():
        try: row=next(iterator)
        except StopIteration: return False
        pending[pool.submit(check_singbox,row['uri'],binary,timeout,cancel_event)]=row['id']; return True
    try:
        for _ in range(min(workers,total)): submit_one()
        while pending:
            while pause_event and pause_event.is_set():
                if cancel_event and cancel_event.is_set(): raise CheckCancelled('Полная проверка отменена',results)
                time.sleep(.1)
            if cancel_event and cancel_event.is_set(): raise CheckCancelled('Полная проверка отменена',results)
            done,_=wait(tuple(pending),timeout=.2,return_when=FIRST_COMPLETED)
            if not done: continue
            for future in done:
                cid=pending.pop(future)
                try: status,latency,error=future.result()
                except Exception as exc: status,latency,error='unreachable',None,str(exc)[:250]
                results.append((cid,status,latency,error)); completed+=1
                if progress: progress(completed,total,results[-1])
                if cancel_event and cancel_event.is_set(): raise CheckCancelled('Полная проверка отменена',results)
                submit_one()
    except CheckCancelled:
        for future in pending: future.cancel()
        pool.shutdown(wait=False,cancel_futures=True); raise
    else: pool.shutdown(wait=True)
    return results
