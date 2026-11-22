import tempfile, unittest, zipfile
from pathlib import Path
from vpn_desk.importer import read_file

class ImporterTests(unittest.TestCase):
    def test_zip_import(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'bundle.zip'
            with zipfile.ZipFile(p,'w') as z:z.writestr('nested.txt','vless://u@example.com:443')
            items,errors,digest=read_file(p)
            self.assertEqual(len(items),1); self.assertEqual(items[0].protocol,'vless'); self.assertFalse(errors); self.assertTrue(digest)
    def test_broken_zip(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'broken.zip'; p.write_bytes(b'not a zip')
            with self.assertRaises(ValueError):read_file(p)


    def test_nested_zip_is_reported_not_extracted(self):
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'nested.zip'
            with zipfile.ZipFile(p,'w') as z:z.writestr('inside.zip',b'PK\x03\x04')
            items,errors,digest=read_file(p)
            self.assertEqual(items,[])
            self.assertTrue(any('Вложенные ZIP' in message for _,message in errors))

    def test_zip_entry_count_limit(self):
        import vpn_desk.importer as importer
        with tempfile.TemporaryDirectory() as d:
            p=Path(d)/'many.zip'
            with zipfile.ZipFile(p,'w') as z:
                z.writestr('a.txt','vless://u@a.example:443')
                z.writestr('b.txt','vless://u@b.example:443')
            old=importer.MAX_ARCHIVE_ENTRIES; importer.MAX_ARCHIVE_ENTRIES=1
            try:
                with self.assertRaises(ValueError):read_file(p)
            finally: importer.MAX_ARCHIVE_ENTRIES=old

if __name__=='__main__':unittest.main()
