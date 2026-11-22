import tempfile, unittest
from pathlib import Path
from vpn_desk.database import Database
from vpn_desk.models import ParsedItem

class DatabaseTests(unittest.TestCase):
    def test_quarantine_after_five_failures_and_manual_recovery(self):
        with tempfile.TemporaryDirectory() as d:
            db=Database(Path(d)/'db.sqlite'); sid,_=db.add_source('https://example.com/list')
            for _ in range(4): db.update_source_result(sid,False,'timeout')
            self.assertEqual(db.rows('sources')[0]['status'],'active')
            db.update_source_result(sid,False,'timeout')
            self.assertEqual(db.rows('sources')[0]['status'],'quarantine')
            db.update_source_result(sid,True)
            self.assertEqual(db.rows('sources')[0]['status'],'active')
            db.close()
    def test_duplicate_config(self):
        with tempfile.TemporaryDirectory() as d:
            db=Database(Path(d)/'db.sqlite'); item=ParsedItem('config','vless://u@h:443','vless','h',443)
            self.assertTrue(db.add_config(item)); self.assertFalse(db.add_config(item)); db.close()


    def test_same_config_keeps_multiple_source_links(self):
        with tempfile.TemporaryDirectory() as d:
            db=Database(Path(d)/'db.sqlite')
            s1,_=db.add_source('https://one.example/list')
            s2,_=db.add_source('https://two.example/list')
            item=ParsedItem('config','vless://u@h.example:443','vless','h.example',443)
            self.assertTrue(db.add_config(item,s1))
            self.assertFalse(db.add_config(item,s2))
            with db.lock:
                count=db.conn.execute('SELECT COUNT(*) FROM config_sources').fetchone()[0]
            self.assertEqual(count,2)
            self.assertEqual({x['configs_total'] for x in db.source_ratings()}, {1})
            db.close()

    def test_rating_softens_single_failure(self):
        with tempfile.TemporaryDirectory() as d:
            db=Database(Path(d)/'db.sqlite'); sid,_=db.add_source('https://free.example/list')
            db.record_source_result(sid,True,configs_found=10,elapsed_ms=500)
            before=db.source_ratings()[0]['rating']
            db.record_source_result(sid,False,'timeout',error_type='timeout')
            after=db.source_ratings()[0]['rating']
            self.assertGreater(after, before-10)
            self.assertLessEqual(after,before)
            db.close()

    def test_energy_selection_distributes_across_sources(self):
        with tempfile.TemporaryDirectory() as d:
            db=Database(Path(d)/'db.sqlite')
            s1,_=db.add_source('https://one.example/list'); s2,_=db.add_source('https://two.example/list')
            for i in range(5):
                db.add_config(ParsedItem('config',f'vless://u{i}@one.example:{1000+i}','vless','one.example',1000+i),s1)
            for i in range(2):
                db.add_config(ParsedItem('config',f'vless://v{i}@two.example:{2000+i}','vless','two.example',2000+i),s2)
            selected=db.select_energy_configs(4)
            with db.lock:
                ids=[r['id'] for r in selected]
                sources=db.conn.execute('SELECT source_id,COUNT(*) n FROM config_sources WHERE config_id IN (%s) GROUP BY source_id' % ','.join('?'*len(ids)),ids).fetchall()
            self.assertEqual(len(selected),4)
            self.assertEqual({r['source_id'] for r in sources},{s1,s2})
            db.close()


    def test_config_metrics_are_smoothed(self):
        with tempfile.TemporaryDirectory() as d:
            db=Database(Path(d)/'db.sqlite')
            item=ParsedItem('config','vless://u@metrics.example:443','vless','metrics.example',443)
            db.add_config(item)
            cid=db.rows('configs')[0]['id']
            db.update_config_result(cid,'reachable',100)
            db.update_config_result(cid,'unreachable',None,error='timeout')
            metrics=db.config_metrics()[cid]
            self.assertEqual(metrics['samples'],2)
            self.assertGreater(metrics['stability'],50)
            self.assertIsNotNone(metrics['quality'])
            db.close()


    def test_migrates_previous_schema(self):
        with tempfile.TemporaryDirectory() as d:
            path=Path(d)/'old.sqlite'
            import sqlite3
            conn=sqlite3.connect(path)
            conn.executescript("""CREATE TABLE sources(id INTEGER PRIMARY KEY,url TEXT NOT NULL UNIQUE,status TEXT NOT NULL DEFAULT 'active',failures INTEGER NOT NULL DEFAULT 0,last_error TEXT NOT NULL DEFAULT '',last_checked TEXT NOT NULL DEFAULT '',created_at TEXT NOT NULL); CREATE TABLE configs(id INTEGER PRIMARY KEY,fingerprint TEXT NOT NULL UNIQUE,uri TEXT NOT NULL,protocol TEXT NOT NULL,host TEXT NOT NULL,port INTEGER NOT NULL,status TEXT NOT NULL DEFAULT 'new',latency_ms REAL,last_checked TEXT NOT NULL DEFAULT '',source_id INTEGER REFERENCES sources(id) ON DELETE SET NULL,created_at TEXT NOT NULL);""")
            conn.execute("INSERT INTO sources(url,created_at) VALUES('https://old.example/list','2025-01-01T00:00:00+00:00')")
            conn.commit(); conn.close()
            db=Database(path)
            cols={r['name'] for r in db.conn.execute('PRAGMA table_info(sources)')}
            self.assertIn('enabled',cols); self.assertIn('check_count',cols)
            self.assertEqual(db.integrity_check(),'ok'); db.close()

    def test_import_batch_commits_source_and_config(self):
        with tempfile.TemporaryDirectory() as d:
            db=Database(Path(d)/'db.sqlite')
            items=[ParsedItem('source','https://batch.example/list'),ParsedItem('config','vless://u@batch.example:443','vless','batch.example',443)]
            added,skipped=db.import_batch(items,'batch.txt','abc',0)
            self.assertEqual((added,skipped),(2,0))
            self.assertEqual(db.stats()['sources'],1); self.assertEqual(db.stats()['configs'],1)
            db.close()


    def test_transient_http_429_does_not_increment_quarantine_failures(self):
        with tempfile.TemporaryDirectory() as d:
            db=Database(Path(d)/'db.sqlite'); sid,_=db.add_source('https://limited.example/list')
            for _ in range(6):
                db.record_source_result(sid,False,'HTTP 429',error_type='HTTP 429',http_code=429,transient=True)
            row=db.rows('sources')[0]
            self.assertEqual(row['failures'],0)
            self.assertEqual(row['status'],'active')
            db.close()

    def test_source_rating_uses_config_ping(self):
        with tempfile.TemporaryDirectory() as d:
            db=Database(Path(d)/'db.sqlite'); sid,_=db.add_source('https://ping.example/list')
            item=ParsedItem('config','vless://u@ping.example:443','vless','ping.example',443)
            db.add_config(item,sid); cid=db.rows('configs')[0]['id']
            db.record_source_result(sid,True,configs_found=1,elapsed_ms=200)
            db.update_config_result(cid,'reachable',50)
            rating_fast=db.source_ratings()[0]['rating']
            db.update_config_result(cid,'reachable',2500)
            rating_slow=db.source_ratings()[0]['rating']
            self.assertGreater(rating_fast,rating_slow)
            db.close()

if __name__=='__main__':unittest.main()
