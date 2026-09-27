"""Validação de chaves privadas no formato próprio do grupo."""
import base64
import json
from pathlib import Path
import tempfile
import unittest

from rsa_keygen import (generate_keypair, export_private_key, import_private_key,
                        KeyFormatError, mod_inverse, gcd)
from rsa_crypto import rsa_pss_sign, rsa_pss_verify, rsa_oaep_encrypt, rsa_oaep_decrypt


def encoded(value):
    return base64.b64encode(value.to_bytes(max(1, (value.bit_length()+7)//8), 'big')).decode()


class PrivateKeyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.public, cls.private = generate_keypair()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.path = Path(self.directory.name) / 'private.json'
        export_private_key(self.private, self.path)
        self.document = json.loads(self.path.read_text())

    def reject(self, document):
        self.path.write_text(json.dumps(document))
        with self.assertRaises(KeyFormatError):
            import_private_key(self.path)

    def test_round_trip_and_operations(self):
        key = import_private_key(self.path)
        self.assertEqual(key, self.private)
        message = b'chave importada'
        self.assertTrue(rsa_pss_verify(self.public, message, rsa_pss_sign(key, message)))
        self.assertEqual(rsa_oaep_decrypt(key, rsa_oaep_encrypt(self.public, message)), message)

    def test_missing_required_fields(self):
        for field in self.document.keys() - {'created_at'}:
            with self.subTest(field=field):
                data = dict(self.document)
                del data[field]
                self.reject(data)

    def test_metadata(self):
        for field, value in [('algorithm', 'INVALIDO'), ('format', 'v2'),
                             ('key_size_bits', 1), ('key_size_bits', '2048'),
                             ('key_size_bits', True), ('key_size_bits', 2048.0)]:
            with self.subTest(field=field, value=value):
                self.reject(dict(self.document, **{field: value}))

    def test_all_numeric_fields_changed(self):
        for field in ('n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qinv'):
            for value in (0, 1, self.private[field] + 2):
                with self.subTest(field=field, value=value):
                    self.reject(dict(self.document, **{field: encoded(value)}))

    def test_invalid_base64(self):
        for field in ('n', 'e', 'd', 'p', 'q', 'dp', 'dq', 'qinv'):
            for value in ('', '%%%', 'Zh==', None, 12, []):
                with self.subTest(field=field, value=value):
                    self.reject(dict(self.document, **{field: value}))

    def test_noncanonical_private_parameters(self):
        phi = (self.private['p'] - 1) * (self.private['q'] - 1)
        for field, value in [('d', self.private['d'] + phi),
                             ('qinv', self.private['qinv'] + self.private['p']),
                             ('p', self.private['q'])]:
            with self.subTest(field=field):
                self.reject(dict(self.document, **{field: encoded(value)}))

    def test_composite_factors_with_consistent_equations(self):
        # Satisfaz as relações algébricas, mas p é composto por construção.
        p, q = self.private['p'] * 3, self.private['q']
        phi = (p - 1) * (q - 1)
        e = 3
        while gcd(e, phi) != 1:
            e += 2
        d = mod_inverse(e, phi)
        params = dict(n=p*q, e=e, d=d, p=p, q=q,
                      dp=d % (p-1), dq=d % (q-1), qinv=mod_inverse(q, p))
        document = dict(self.document, key_size_bits=(p*q).bit_length())
        document.update({field: encoded(value) for field, value in params.items()})
        self.reject(document)

    def test_malformed_json(self):
        for text in ('{', 'null', '[]', '{"n":1,"n":2}'):
            with self.subTest(text=text):
                self.path.write_text(text)
                with self.assertRaises(KeyFormatError):
                    import_private_key(self.path)
