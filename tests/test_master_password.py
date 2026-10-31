import unittest

from vault import PH, verify_master

class TestMasterPassword(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.password = "Only-For-Testing-2026!"
        cls.vault = {
            "master_hash": PH.hash(cls.password)
        }

    def test_correct_password_is_accepted(self):
        verify_master(self.vault, self.password)

    def test_wrong_password_is_rejected(self):
        with self.assertRaises(SystemExit) as result:
            verify_master(self.vault, "wrong-password")

        self.assertEqual(result.exception.code, 1)