import unittest
import asymmetric_jwt_auth as auth


class UtilsTest(unittest.TestCase):
    def test_generate_new_key(self):
        private, public = auth.generate_key_pair()

        private = private.strip().split('\n')
        self.assertEqual(private[0], '-----BEGIN PRIVATE KEY-----')
        self.assertEqual(private[27], '-----END PRIVATE KEY-----')

        public = public.strip().split('\n')
        self.assertEqual(public[0], '-----BEGIN PUBLIC KEY-----')
        self.assertEqual(public[8], '-----END PUBLIC KEY-----')
