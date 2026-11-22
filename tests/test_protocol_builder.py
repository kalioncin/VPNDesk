import base64
import json
import unittest
from vpn_desk.checker import build_singbox_outbound

class ProtocolBuilderTests(unittest.TestCase):
    def test_vless_ws_reality_options(self):
        uri='vless://12345678-1234-1234-1234-123456789abc@example.com:443?security=reality&sni=cdn.example.com&pbk=PUBLICKEY&sid=abcd&type=ws&path=%2Fedge'
        out=build_singbox_outbound(uri)
        self.assertEqual(out['type'],'vless')
        self.assertEqual(out['tls']['reality']['public_key'],'PUBLICKEY')
        self.assertEqual(out['transport']['type'],'ws')
    def test_trojan_tls(self):
        out=build_singbox_outbound('trojan://secret@example.com:443?sni=example.com')
        self.assertEqual(out['password'],'secret')
        self.assertTrue(out['tls']['enabled'])
    def test_shadowsocks_base64_userinfo(self):
        encoded=base64.urlsafe_b64encode(b'aes-256-gcm:secret').decode().rstrip('=')
        out=build_singbox_outbound(f'ss://{encoded}@example.com:8388')
        self.assertEqual(out['method'],'aes-256-gcm')
        self.assertEqual(out['password'],'secret')
    def test_hysteria2(self):
        out=build_singbox_outbound('hysteria2://secret@example.com:443?sni=example.com')
        self.assertEqual(out['type'],'hysteria2')
        self.assertEqual(out['password'],'secret')
    def test_tuic(self):
        out=build_singbox_outbound('tuic://12345678-1234-1234-1234-123456789abc:secret@example.com:443?sni=example.com')
        self.assertEqual(out['type'],'tuic')
        self.assertEqual(out['password'],'secret')
    def test_vmess(self):
        data={'add':'example.com','port':'443','id':'12345678-1234-1234-1234-123456789abc','aid':'0','scy':'auto','net':'ws','tls':'tls','path':'/ws','host':'cdn.example.com'}
        payload=base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip('=')
        out=build_singbox_outbound('vmess://'+payload)
        self.assertEqual(out['type'],'vmess')
        self.assertEqual(out['transport']['type'],'ws')
    def test_unsupported_transport_is_not_guessed(self):
        with self.assertRaises(ValueError):
            build_singbox_outbound('vless://12345678-1234-1234-1234-123456789abc@example.com:443?type=kcp')

if __name__=='__main__': unittest.main()
