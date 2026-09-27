"""Regressões para decifragem OAEP e limites da codificação SHA3-256."""
import hashlib
import unittest
from unittest.mock import patch

from rsa_crypto import i2osp, mgf1, xor_bytes, rsa_oaep_encrypt, rsa_oaep_decrypt
from rsa_keygen import generate_keypair, mod_exp


class OAEPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.public, cls.private = generate_keypair()

    def assert_rejected(self, ciphertext, label=b""):
        with self.assertRaisesRegex(ValueError, r"^Erro de decifragem OAEP\.$"):
            rsa_oaep_decrypt(self.private, ciphertext, label)

    def encode_block(self, db, leading_byte=0):
        # Monta blocos controlados sem passar pelo codificador que está sob teste.
        seed = bytes(range(32))
        masked_db = xor_bytes(db, mgf1(seed, 223))
        masked_seed = xor_bytes(seed, mgf1(masked_db, 32))
        encoded = bytes([leading_byte]) + masked_seed + masked_db
        return i2osp(mod_exp(int.from_bytes(encoded, "big"), self.public["e"], self.public["n"]), 256)

    def test_round_trip_and_message_limits(self):
        for message in (b"", b"mensagem", bytes(range(190))):
            with self.subTest(length=len(message)):
                ciphertext = rsa_oaep_encrypt(self.public, message)
                self.assertEqual(len(ciphertext), 256)
                self.assertEqual(rsa_oaep_decrypt(self.private, ciphertext), message)
        with self.assertRaises(ValueError):
            rsa_oaep_encrypt(self.public, b"x" * 191)

    def test_label_and_randomness(self):
        first = rsa_oaep_encrypt(self.public, b"teste", b"contexto")
        second = rsa_oaep_encrypt(self.public, b"teste", b"contexto")
        self.assertNotEqual(first, second)
        self.assertEqual(rsa_oaep_decrypt(self.private, first, b"contexto"), b"teste")
        self.assert_rejected(first, b"outro")

    def test_changed_ciphertext_and_invalid_lengths(self):
        ciphertext = rsa_oaep_encrypt(self.public, b"teste")
        altered = bytearray(ciphertext)
        altered[128] ^= 1
        for value in (bytes(altered), b"", ciphertext[:-1], ciphertext + b"\0"):
            with self.subTest(length=len(value)):
                self.assert_rejected(value)

    def test_out_of_range_rejected_before_rsa(self):
        for value in (self.public["n"], self.public["n"] + 1, (1 << 2048) - 1):
            with self.subTest(value=value), patch("rsa_crypto.mod_exp") as operation:
                self.assert_rejected(i2osp(value, 256))
                operation.assert_not_called()

    def test_malformed_padding(self):
        valid = hashlib.sha3_256(b"").digest() + b"\0" * 185 + b"\x01teste"
        self.assertEqual(rsa_oaep_decrypt(self.private, self.encode_block(valid)), b"teste")
        for index in (32, 100, 216):
            altered = bytearray(valid)
            altered[index] = 2
            with self.subTest(padding_index=index):
                self.assert_rejected(self.encode_block(bytes(altered)))
        self.assert_rejected(self.encode_block(valid, leading_byte=1))
        wrong_hash = bytearray(valid)
        wrong_hash[0] ^= 1
        self.assert_rejected(self.encode_block(bytes(wrong_hash)))
        self.assert_rejected(self.encode_block(valid[:32] + b"\0" * 191))

    def test_binary_message_after_separator(self):
        # Os bytes após 0x01 pertencem à mensagem, inclusive 0x00, 0x01 e 0x02.
        message = b"\x00\x01\x02\xff"
        db = hashlib.sha3_256(b"").digest() + b"\0" * 186 + b"\x01" + message
        self.assertEqual(rsa_oaep_decrypt(self.private, self.encode_block(db)), message)

    def test_invalid_key_parameters(self):
        ciphertext = rsa_oaep_encrypt(self.public, b"teste")
        for field, value in (("key_size_bits", 1), ("d", 0), ("d", -1)):
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                rsa_oaep_decrypt(dict(self.private, **{field: value}), ciphertext)

    def test_non_byte_aligned_modulus(self):
        public, private = generate_keypair(2049)
        message = bytes(range(191))
        ciphertext = rsa_oaep_encrypt(public, message)
        self.assertEqual(len(ciphertext), 257)
        self.assertEqual(rsa_oaep_decrypt(private, ciphertext), message)
        with self.assertRaises(ValueError):
            rsa_oaep_encrypt(public, message + b"x")
