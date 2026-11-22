from __future__ import annotations

import hashlib
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


class Database:
    """SQLite storage with migrations, provenance and append-only check history."""

    TABLES = {'sources', 'configs', 'events', 'imports', 'config_checks', 'source_checks'}

    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(self.path, check_same_thread=False, timeout=15)
        self.conn.row_factory = sqlite3.Row
        with self.lock:
            self.conn.execute('PRAGMA foreign_keys=ON')
            self.conn.execute('PRAGMA journal_mode=WAL')
            self.conn.execute('PRAGMA synchronous=NORMAL')
            self.conn.execute('PRAGMA busy_timeout=15000')
            self.conn.executescript('''
            CREATE TABLE IF NOT EXISTS sources(
              id INTEGER PRIMARY KEY, url TEXT NOT NULL UNIQUE,
              status TEXT NOT NULL DEFAULT 'active', enabled INTEGER NOT NULL DEFAULT 1,
              failures INTEGER NOT NULL DEFAULT 0, check_count INTEGER NOT NULL DEFAULT 0,
              success_count INTEGER NOT NULL DEFAULT 0, last_error TEXT NOT NULL DEFAULT '',
              last_checked TEXT NOT NULL DEFAULT '', last_success_at TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS configs(
              id INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE, uri TEXT NOT NULL,
              protocol TEXT NOT NULL, host TEXT NOT NULL, port INTEGER NOT NULL,
              status TEXT NOT NULL DEFAULT 'new', latency_ms REAL, last_checked TEXT NOT NULL DEFAULT '',
              source_id INTEGER REFERENCES sources(id) ON DELETE SET NULL, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS config_sources(
              config_id INTEGER NOT NULL REFERENCES configs(id) ON DELETE CASCADE,
              source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
              first_seen TEXT NOT NULL, last_seen TEXT NOT NULL,
              PRIMARY KEY(config_id, source_id));
            CREATE TABLE IF NOT EXISTS config_checks(
              id INTEGER PRIMARY KEY, config_id INTEGER NOT NULL REFERENCES configs(id) ON DELETE CASCADE,
              checked_at TEXT NOT NULL, status TEXT NOT NULL, latency_ms REAL,
              error TEXT NOT NULL DEFAULT '', check_kind TEXT NOT NULL DEFAULT 'tcp');
            CREATE TABLE IF NOT EXISTS source_checks(
              id INTEGER PRIMARY KEY, source_id INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
              checked_at TEXT NOT NULL, success INTEGER NOT NULL, error_type TEXT NOT NULL DEFAULT '',
              http_code INTEGER, configs_found INTEGER NOT NULL DEFAULT 0, elapsed_ms REAL);
            CREATE TABLE IF NOT EXISTS events(
              id INTEGER PRIMARY KEY, created_at TEXT NOT NULL, level TEXT NOT NULL, message TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS imports(
              id INTEGER PRIMARY KEY, filename TEXT NOT NULL, digest TEXT NOT NULL,
              added INTEGER NOT NULL, skipped INTEGER NOT NULL, errors INTEGER NOT NULL,
              created_at TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS idx_configs_status ON configs(status);
            CREATE INDEX IF NOT EXISTS idx_config_checks_config_date ON config_checks(config_id, checked_at);
            CREATE INDEX IF NOT EXISTS idx_source_checks_source_date ON source_checks(source_id, checked_at);
            CREATE INDEX IF NOT EXISTS idx_events_date ON events(created_at);
            ''')
            self._migrate_columns()
            self.conn.execute('''INSERT OR IGNORE INTO config_sources(config_id,source_id,first_seen,last_seen)
                SELECT id,source_id,created_at,created_at FROM configs WHERE source_id IS NOT NULL''')
            self.conn.commit()

    def _migrate_columns(self):
        existing = {r['name'] for r in self.conn.execute('PRAGMA table_info(sources)')}
        additions = {
            'enabled': 'INTEGER NOT NULL DEFAULT 1',
            'check_count': 'INTEGER NOT NULL DEFAULT 0',
            'success_count': 'INTEGER NOT NULL DEFAULT 0',
            'last_success_at': "TEXT NOT NULL DEFAULT ''",
        }
        for name, definition in additions.items():
            if name not in existing:
                self.conn.execute(f'ALTER TABLE sources ADD COLUMN {name} {definition}')

    def add_event(self, message: str, level: str = 'INFO'):
        with self.lock, self.conn:
            self.conn.execute('INSERT INTO events(created_at,level,message) VALUES(?,?,?)',
                              (now(), level, str(message)[:1000]))

    def add_source(self, url: str):
        url = url.strip()
        with self.lock, self.conn:
            cur = self.conn.execute('INSERT OR IGNORE INTO sources(url,created_at) VALUES(?,?)', (url, now()))
            row = self.conn.execute('SELECT id FROM sources WHERE url=?', (url,)).fetchone()
            return row['id'], cur.rowcount == 1

    def update_source(self, source_id: int, url: str):
        with self.lock, self.conn:
            self.conn.execute('UPDATE sources SET url=? WHERE id=?', (url.strip(), source_id))

    def set_source_enabled(self, source_id: int, enabled: bool):
        with self.lock, self.conn:
            status = 'active' if enabled else 'disabled'
            self.conn.execute('UPDATE sources SET enabled=?,status=? WHERE id=?',
                              (int(enabled), status, source_id))

    def delete_source(self, source_id: int):
        with self.lock, self.conn:
            self.conn.execute('DELETE FROM sources WHERE id=?', (source_id,))

    def add_config(self, item, source_id=None) -> bool:
        fingerprint = hashlib.sha256(item.value.encode('utf-8')).hexdigest()
        stamp = now()
        with self.lock, self.conn:
            cur = self.conn.execute('''INSERT OR IGNORE INTO configs
                (fingerprint,uri,protocol,host,port,source_id,created_at)
                VALUES(?,?,?,?,?,?,?)''',
                (fingerprint, item.value, item.protocol, item.host, item.port, source_id, stamp))
            row = self.conn.execute('SELECT id FROM configs WHERE fingerprint=?', (fingerprint,)).fetchone()
            if source_id is not None and row:
                self.conn.execute('''INSERT INTO config_sources(config_id,source_id,first_seen,last_seen)
                    VALUES(?,?,?,?) ON CONFLICT(config_id,source_id) DO UPDATE SET last_seen=excluded.last_seen''',
                    (row['id'], source_id, stamp, stamp))
            return cur.rowcount == 1

    def import_batch(self, items, filename: str, digest: str = '', errors: int = 0):
        """Commit a complete previewed import atomically; returns added/skipped counts."""
        added = skipped = 0
        stamp = now()
        with self.lock:
            with self.conn:
                for item in items:
                    if item.kind == 'source':
                        cur = self.conn.execute(
                            'INSERT OR IGNORE INTO sources(url,created_at) VALUES(?,?)',
                            (item.value, stamp))
                    else:
                        fingerprint = hashlib.sha256(item.value.encode('utf-8')).hexdigest()
                        cur = self.conn.execute(
                            'INSERT OR IGNORE INTO configs(fingerprint,uri,protocol,host,port,source_id,created_at) VALUES(?,?,?,?,?,?,?)',
                            (fingerprint, item.value, item.protocol, item.host, item.port, None, stamp))
                    if cur.rowcount == 1:
                        added += 1
                    else:
                        skipped += 1
                self.conn.execute(
                    'INSERT INTO imports(filename,digest,added,skipped,errors,created_at) VALUES(?,?,?,?,?,?)',
                    (filename, digest, added, skipped, errors, stamp))
        return added, skipped

    def record_import(self, filename, digest, added, skipped, errors):
        with self.lock, self.conn:
            self.conn.execute('INSERT INTO imports(filename,digest,added,skipped,errors,created_at) VALUES(?,?,?,?,?,?)',
                              (filename, digest, added, skipped, errors, now()))

    def rows(self, table: str, limit: int = 500):
        if table not in self.TABLES:
            raise ValueError('Invalid table')
        with self.lock:
            return self.conn.execute(f'SELECT * FROM {table} ORDER BY id DESC LIMIT ?',
                                      (max(1, min(int(limit), 1_000_000)),)).fetchall()

    def stats(self):
        with self.lock:
            return {name: self.conn.execute(sql).fetchone()[0] for name, sql in {
                'sources': 'SELECT COUNT(*) FROM sources',
                'active_sources': "SELECT COUNT(*) FROM sources WHERE status='active' AND enabled=1",
                'quarantined': "SELECT COUNT(*) FROM sources WHERE status='quarantine'",
                'disabled_sources': "SELECT COUNT(*) FROM sources WHERE enabled=0",
                'configs': 'SELECT COUNT(*) FROM configs',
                'reachable': "SELECT COUNT(*) FROM configs WHERE status='reachable'",
                'unreachable': "SELECT COUNT(*) FROM configs WHERE status='unreachable'",
                'unchecked': "SELECT COUNT(*) FROM configs WHERE status='new'",
            }.items()}

    def record_source_result(self, source_id: int, success: bool, error: str = '', *,
                             error_type: str = '', http_code: int | None = None,
                             configs_found: int = 0, elapsed_ms: float | None = None,
                             transient: bool = False):
        stamp = now()
        with self.lock, self.conn:
            self.conn.execute('''INSERT INTO source_checks
                (source_id,checked_at,success,error_type,http_code,configs_found,elapsed_ms)
                VALUES(?,?,?,?,?,?,?)''',
                (source_id, stamp, int(success), error_type[:80], http_code, configs_found, elapsed_ms))
            row = self.conn.execute('SELECT failures,check_count,success_count,status FROM sources WHERE id=?',
                                    (source_id,)).fetchone()
            if not row:
                return
            checks = row['check_count'] + 1
            successes = row['success_count'] + int(success)
            if success:
                status, failures, last_error, last_success = 'active', 0, '', stamp
            elif transient:
                status, failures, last_error, last_success = row['status'], row['failures'], error[:500], ''
            else:
                failures = row['failures'] + 1
                status = 'quarantine' if failures >= 5 else row['status']
                last_error, last_success = error[:500], ''
            self.conn.execute('''UPDATE sources SET status=?,failures=?,check_count=?,success_count=?,
                last_error=?,last_checked=?,last_success_at=CASE WHEN ?='' THEN last_success_at ELSE ? END
                WHERE id=?''',
                (status, failures, checks, successes, last_error, stamp, last_success, last_success, source_id))

    def update_source_result(self, source_id, success, error=''):
        """Compatibility wrapper for older callers/tests."""
        self.record_source_result(source_id, success, error,
                                  error_type='network' if error else '', transient=False)

    def update_config_result(self, config_id: int, status: str, latency=None, error: str = '',
                             check_kind: str = 'tcp'):
        stamp = now()
        with self.lock, self.conn:
            self.conn.execute('UPDATE configs SET status=?,latency_ms=?,last_checked=? WHERE id=?',
                              (status, latency, stamp, config_id))
            self.conn.execute('''INSERT INTO config_checks(config_id,checked_at,status,latency_ms,error,check_kind)
                VALUES(?,?,?,?,?,?)''', (config_id, stamp, status, latency, error[:300], check_kind))

    def source_ratings(self):
        """Soft 0..100 source score; sparse/temporary failures are deliberately smoothed."""
        with self.lock:
            sources = self.conn.execute('SELECT * FROM sources').fetchall()
            result = []
            for source in sources:
                checks = self.conn.execute('''SELECT success,configs_found,elapsed_ms,checked_at
                    FROM source_checks WHERE source_id=? ORDER BY id DESC LIMIT 100''',
                    (source['id'],)).fetchall()
                if not checks:
                    score = 50.0
                    success_rate = None
                    median_latency = None
                else:
                    n = len(checks)
                    raw_rate = sum(r['success'] for r in checks) / n
                    # Strong prior and low sample confidence keep free/ephemeral sources from collapsing.
                    confidence = n / (n + 8.0)
                    smooth_rate = 0.65 + (raw_rate - 0.65) * confidence
                    freshness = 0.0
                    try:
                        age_days = max(0.0, (datetime.now(timezone.utc) - datetime.fromisoformat(checks[0]['checked_at'])).total_seconds()/86400)
                        freshness = max(0.0, 1.0 - age_days/30.0)
                    except (ValueError, TypeError):
                        pass
                    source_fetch_score = smooth_rate
                    success_rate = smooth_rate
                linked = self.conn.execute('''SELECT COUNT(*) AS total,
                    SUM(CASE WHEN c.status='reachable' THEN 1 ELSE 0 END) AS reachable,
                    SUM(CASE WHEN c.status='unreachable' THEN 1 ELSE 0 END) AS unreachable
                    FROM config_sources cs JOIN configs c ON c.id=cs.config_id WHERE cs.source_id=?''',
                    (source['id'],)).fetchone()
                tested = (linked['reachable'] or 0) + (linked['unreachable'] or 0)
                raw_alive = (linked['reachable'] or 0) / tested if tested else 0.65
                config_confidence = tested / (tested + 10.0)
                config_health = 0.65 + (raw_alive - 0.65) * config_confidence
                with self.conn:
                    ping_rows = self.conn.execute('''SELECT cc.latency_ms FROM config_checks cc
                        JOIN config_sources cs ON cs.config_id=cc.config_id
                        WHERE cs.source_id=? AND cc.status='reachable' AND cc.latency_ms IS NOT NULL
                        ORDER BY cc.id DESC LIMIT 200''', (source['id'],)).fetchall()
                latencies = sorted(float(r['latency_ms']) for r in ping_rows)
                median_latency = latencies[len(latencies)//2] if latencies else None
                latency_score = 0.7 if median_latency is None else max(0.25, 1.0 - min(median_latency, 3000)/4000)
                if not checks:
                    source_fetch_score = 0.65
                    freshness = 0.0
                    sample_score = 0.0
                    success_rate = None
                else:
                    sample_score = min(1.0,len(checks)/10.0)
                score = 35*source_fetch_score + 25*config_health + 20*freshness + 10*latency_score + 10*sample_score
                if source['enabled'] == 0:
                    score *= 0.8
                result.append({**dict(source), 'rating': round(max(0,min(100,score)),1),
                               'success_rate': None if success_rate is None else round(success_rate*100,1),
                               'median_latency_ms': median_latency, 'samples': len(checks),
                               'configs_total': linked['total'] or 0,
                               'configs_reachable': linked['reachable'] or 0,
                               'configs_unreachable': linked['unreachable'] or 0})
            return sorted(result, key=lambda x: (-x['rating'], x['id']))

    def select_energy_configs(self, limit: int):
        """Fair per-source quota, then redistribute unused quota to highest-rated sources."""
        limit = max(1, int(limit))
        ratings = self.source_ratings()
        source_ids = [r['id'] for r in ratings if r['enabled'] and r['status'] == 'active']
        with self.lock:
            def source_rows(source_id):
                return self.conn.execute('''SELECT c.* FROM configs c JOIN config_sources cs ON cs.config_id=c.id
                    WHERE cs.source_id=? ORDER BY CASE c.status WHEN 'new' THEN 0 WHEN 'unreachable' THEN 1 ELSE 2 END,
                    c.last_checked,c.id''', (source_id,)).fetchall()
            selected = []
            selected_ids = set()
            pools = {sid: source_rows(sid) for sid in source_ids}
            if not pools:
                return self.conn.execute('''SELECT * FROM configs ORDER BY CASE status WHEN 'new' THEN 0
                    WHEN 'unreachable' THEN 1 ELSE 2 END,last_checked,id LIMIT ?''', (limit,)).fetchall()
            base_quota = limit // len(pools)
            for sid in source_ids:
                for row in pools[sid][:base_quota]:
                    if row['id'] not in selected_ids and len(selected) < limit:
                        selected.append(row); selected_ids.add(row['id'])
            # Fill unused slots in descending source-rating order.
            for sid in source_ids:
                for row in pools[sid]:
                    if len(selected) >= limit: break
                    if row['id'] not in selected_ids:
                        selected.append(row); selected_ids.add(row['id'])
                if len(selected) >= limit: break
            if len(selected) < limit:
                extra = self.conn.execute('''SELECT * FROM configs WHERE id NOT IN
                    (SELECT config_id FROM config_sources) ORDER BY CASE status WHEN 'new' THEN 0
                    WHEN 'unreachable' THEN 1 ELSE 2 END,last_checked,id LIMIT ?''',
                    (limit-len(selected),)).fetchall()
                selected.extend(extra)
            return selected[:limit]

    def config_metrics(self, config_ids=None):
        """Return smoothed stability and latency scores for every configuration."""
        with self.lock:
            if config_ids:
                ids=[int(x) for x in config_ids]
                placeholders=','.join('?' for _ in ids)
                rows=self.conn.execute(f'SELECT config_id,status,latency_ms,checked_at FROM config_checks WHERE config_id IN ({placeholders}) ORDER BY id DESC LIMIT 100000',ids).fetchall()
            else:
                rows=self.conn.execute('SELECT config_id,status,latency_ms,checked_at FROM config_checks ORDER BY id DESC LIMIT 50000').fetchall()
        grouped={}
        for row in rows:
            bucket=grouped.setdefault(row['config_id'],[])
            if len(bucket)<30:bucket.append(row)
        result={}
        for config_id,checks in grouped.items():
            n=len(checks); raw=sum(x['status']=='reachable' for x in checks)/n
            confidence=n/(n+6.0); stability=0.65+(raw-0.65)*confidence
            pings=sorted(float(x['latency_ms']) for x in checks if x['status']=='reachable' and x['latency_ms'] is not None)
            median=pings[len(pings)//2] if pings else None
            ping_score=0.7 if median is None else max(0.25,1-min(median,3000)/4000)
            result[config_id]={'stability':round(stability*100,1),'median_latency':median,
                'quality':round(max(0,min(100,75*stability+25*ping_score)),1),'samples':n}
        return result

    def config_history(self, config_id: int, limit: int = 100):
        with self.lock:
            return self.conn.execute('''SELECT * FROM config_checks WHERE config_id=?
                ORDER BY id DESC LIMIT ?''', (config_id, limit)).fetchall()

    def source_history(self, source_id: int, limit: int = 100):
        with self.lock:
            return self.conn.execute('''SELECT * FROM source_checks WHERE source_id=?
                ORDER BY id DESC LIMIT ?''', (source_id, limit)).fetchall()

    def backup(self, destination):
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        with self.lock:
            target = sqlite3.connect(destination)
            try:
                self.conn.backup(target)
            finally:
                target.close()
        return destination

    def integrity_check(self):
        with self.lock:
            return self.conn.execute('PRAGMA integrity_check').fetchone()[0]

    def close(self):
        with self.lock:
            self.conn.close()
