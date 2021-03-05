from django.test import TestCase, override_settings
from .. import get_setting


class SettingsTest(TestCase):

    def test_get_settings_default(self):
        self.assertEqual(get_setting('AUTH_METHOD'), 'JWT')
        self.assertEqual(get_setting('TIMESTAMP_TOLERANCE'), 20)


    @override_settings(ASYMMETRIC_JWT_AUTH=dict(TIMESTAMP_TOLERANCE=30))
    def test_get_setting_overridden(self):
        self.assertEqual(get_setting('AUTH_METHOD'), 'JWT')
        self.assertEqual(get_setting('TIMESTAMP_TOLERANCE'), 30)
