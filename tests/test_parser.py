import unittest, base64, json, io
from vpn_desk.parser import parse_text, parse_config, parse_stream

class ParserTests(unittest.TestCase):
    def test_multiple_links_same_line_and_columns(self):
        text='prefix vless://id@example.com:443?encryption=none#one  trojan://pass@example.net:8443\nss://YWVzLTEyOC1nY206cGFzcw@example.org:8388'
        items,errors=parse_text(text)
        self.assertEqual(len([x for x in items if x.kind=='config']),3)
        self.assertEqual(errors,[])
    def test_source_url(self):
        items,_=parse_text('https://example.com/sub.txt')
        self.assertEqual(items[0].kind,'source')
    def test_deduplicate(self):
        items,_=parse_text('vless://u@host.example:443 vless://u@host.example:443')
        self.assertEqual(len(items),1)
    def test_invalid_port(self):
        with self.assertRaises(ValueError): parse_config('vless://u@host.example:99999')
    def test_stream_keeps_uri_across_chunks(self):
        data=('x'*40+' vless://user@example.com:443\n'+'y'*40).encode()
        items,errors=parse_stream(io.BytesIO(data),chunk_size=13)
        self.assertEqual(len(items),1)
        self.assertEqual(items[0].host,'example.com')
        self.assertFalse(errors)
    def test_vmess(self):
        payload=base64.b64encode(json.dumps({'add':'example.com','port':'443'}).encode()).decode().rstrip('=')
        item=parse_config('vmess://'+payload)
        self.assertEqual((item.host,item.port),('example.com',443))

if __name__=='__main__':unittest.main()
