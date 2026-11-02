import base64
import unittest

from vault import derive_key
from contextlib import redirect_stderr
from io import StringIO


class TestKeyDerivation(unittest.TestCase):
    def setUp(self):
        self.password = "Only-For-Testing-2026!"
        salt = b"0123456789abcdef"

        self.vault = {
            "kdf": {
                "salt_b64": base64.b64encode(salt).decode("ascii"),
                "time_cost": 3,
                "memory_cost": 64*1024,
                "parallelism": 4,
                "hash_len": 32,
            }
        }

    def test_different_password_produce_different_keys(self):
        first_key = derive_key(self.vault, self.password)

        second_key = derive_key(
            self.vault,
            "Another-Testing_Password!",
        )

        self.assertNotEqual(first_key, second_key)

    def test_different_salts_produce_different_keys(self):
        first_key = derive_key(self.vault, self.password)

        other_kdf = self.vault["kdf"].copy()
        other_salt = b"fedcba9876543210"
        other_kdf["salt_b64"] = (
            base64.b64encode(other_salt).decode("ascii")
        )

        second_key = derive_key(
            {"kdf": other_kdf},
            self.password,
        )

        self.assertNotEqual(first_key, second_key)

    def test_key_is_32_bytes(self):
        key = derive_key(self.vault, self.password)

        self.assertIsInstance(key, bytes)
        self.assertEqual(len(key), 32)

    def test_same_inputs_produce_same_key(self):
        first_key = derive_key(self.vault, self.password)
        second_key = derive_key(self.vault, self.password)

        self.assertEqual(first_key, second_key)

    def test_missing_kdf_is_rejected(self):
        error_output = StringIO()

        with redirect_stderr(error_output):
            with self.assertRaises(SystemExit) as result:
                derive_key({}, self.password)

        self.assertEqual(result.exception.code, 1)
        self.assertIn(
            "Vault is missing KDF parameters.",
            error_output.getvalue(),
        )

    def test_null_kdf_is_rejected(self):
        error_output = StringIO()

        with redirect_stderr(error_output):
            with self.assertRaises(SystemExit) as result:
                derive_key({"kdf": None}, self.password)

        self.assertEqual(result.exception.code, 1)
        self.assertIn(
            "Vault KDF parameters must be an object.",
            error_output.getvalue(),
        )