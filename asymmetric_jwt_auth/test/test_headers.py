import unittest
import time
import os.path
from asymmetric_jwt_auth import create_auth_header, generate_key_pair
from asymmetric_jwt_auth.token import verify

BASE = os.path.dirname(os.path.abspath(__file__))

KEY1_PRIVATE = os.path.join(BASE, 'dummy')
KEY1_PUBLIC = os.path.join(BASE, 'dummy.pub')

KEY2_PRIVATE = os.path.join(BASE, 'dummy_encrypted')
KEY2_PUBLIC = os.path.join(BASE, 'dummy_encrypted.pub')
KEY2_PASSWORD = b'password'


class HTTPHeaderTest(unittest.TestCase):
    def test_generate_from_key_string(self):
        private1, public1 = generate_key_pair()
        private2, public2 = generate_key_pair()
        header = create_auth_header('foo', key=private1)
        self.assertTrue(header.startswith('JWT '))
        token = header.split(' ', 1)[1]
        self.assertFalse(verify(token, public2))
        self.assertTrue(verify(token, public1))

    def test_generate_from_key_file(self):
        header = create_auth_header('foo', key_file=KEY1_PRIVATE)
        self.assertTrue(header.startswith('JWT '))
        token = header.split(' ', 1)[1]
        with open(KEY1_PUBLIC, 'r') as public:
            self.assertTrue(verify(token, public.read()))

    def test_generate_from_encrypted_key_file(self):
        header = create_auth_header('foo', key_file=KEY2_PRIVATE, key_password=KEY2_PASSWORD)
        self.assertTrue(header.startswith('JWT '))
        token = header.split(' ', 1)[1]
        with open(KEY2_PUBLIC, 'r') as public:
            self.assertTrue(verify(token, public.read()))
