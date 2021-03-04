from io import StringIO
from django.test import TestCase
from django.core.management import call_command


class ManagementCommandTest(TestCase):
    def test_generate_new_rsa_key(self):
        stdout = StringIO()
        stderr = StringIO()
        call_command('generate_key_pair',
            stdout=stdout,
            stderr=stderr)
        out = stdout.getvalue()
        self.assertIn("-----BEGIN PRIVATE KEY-----\n", out)
        self.assertIn("-----END PRIVATE KEY-----\n", out)
        self.assertIn("-----BEGIN PUBLIC KEY-----\n", out)
        self.assertIn("-----END PUBLIC KEY-----\n", out)
        self.assertTrue(len(out) > 2000)
        self.assertTrue(len(out) < 3000)


    def test_generate_new_ed25519_key(self):
        stdout = StringIO()
        stderr = StringIO()
        call_command('generate_key_pair',
            keytype='Ed25519',
            stdout=stdout,
            stderr=stderr)
        out = stdout.getvalue()
        self.assertIn("-----BEGIN PRIVATE KEY-----\n", out)
        self.assertIn("-----END PRIVATE KEY-----\n", out)
        self.assertIn("-----BEGIN PUBLIC KEY-----\n", out)
        self.assertIn("-----END PUBLIC KEY-----\n", out)
        self.assertTrue(len(out) > 200)
        self.assertTrue(len(out) < 300)
