import os
import unittest
from unittest.mock import patch
from vpn_desk.components import windows_architecture

class ComponentTests(unittest.TestCase):
    def test_detects_amd64(self):
        with patch.dict(os.environ, {'PROCESSOR_ARCHITEW6432':'AMD64','PROCESSOR_ARCHITECTURE':'x86'}, clear=False):
            self.assertEqual(windows_architecture(),'amd64')
    def test_detects_arm64(self):
        with patch.dict(os.environ, {'PROCESSOR_ARCHITECTURE':'ARM64'}, clear=True):
            self.assertEqual(windows_architecture(),'arm64')

if __name__=='__main__':unittest.main()
