"""Vetores de regressão MGF1-SHA3-256; não são vetores oficiais NIST."""
import unittest
from rsa_crypto import mgf1, i2osp, os2ip


class EncodingTests(unittest.TestCase):
    def test_mgf1_fixed_vector(self):
        # SHA3-256(seed || 00000000) || SHA3-256(seed || 00000001).
        # Constante obtida separadamente com hashlib, sem chamar mgf1.
        expected = bytes.fromhex("7fe2e122219eb3f5a8b31f3bab2fa73c7fe7cf915da2b28692a7630a7dd9cd990100e302da9014519654dc979034a12ea9e08423477d1b3cddb0fe840d3c62ae")
        for length in (0, 1, 31, 32, 33, 63, 64):
            with self.subTest(length=length):
                self.assertEqual(mgf1(b'seed', length), expected[:length])

    def test_invalid_mask_lengths(self):
        for length in (-1, 1.5, True, '32', 32 * (1 << 32) + 1):
            with self.subTest(length=length), self.assertRaises(ValueError):
                mgf1(b'seed', length)

    def test_integer_octet_conversion(self):
        self.assertEqual(i2osp(256, 3), b'\x00\x01\x00')
        self.assertEqual(os2ip(b'\x00\x01\x00'), 256)
        self.assertEqual(i2osp(0, 0), b'')
        for integer, length in ((256, 1), (-1, 2)):
            with self.assertRaises(ValueError):
                i2osp(integer, length)
