"""Testes das Partes IV/V; chaves descartáveis geradas pela implementação manual."""
import base64
import contextlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from rsa_crypto import i2osp, rsa_pss_sign, rsa_pss_verify
from rsa_keygen import export_public_key, generate_keypair, import_public_key, KeyFormatError, mod_exp
from signed_file import main, parse_signed_file, serialize_signed_file, verify_signed_file, SignedFileError


class VerificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.public, cls.private = generate_keypair()
        cls.other_public, _ = generate_keypair()
        cls.content = b"Trabalho de seguranca\x00\xff\r\n"
        cls.serialized = serialize_signed_file(cls.content, cls.private)
        cls.structure = json.loads(cls.serialized)
        cls.signature = cls.structure["signature_b64"]

    def test_valid_round_trip(self):
        self.assertEqual(parse_signed_file(self.serialized), (self.content, self.signature))
        self.assertTrue(verify_signed_file(self.serialized, self.public))

    def test_empty_and_binary_files(self):
        for content in (b"", bytes(range(256))):
            with self.subTest(size=len(content)):
                self.assertTrue(verify_signed_file(serialize_signed_file(content, self.private), self.public))

    def test_one_byte_of_file_or_signature_changed(self):
        for field in ("content_b64", "signature_b64"):
            changed = dict(self.structure)
            raw = bytearray(base64.b64decode(changed[field]))
            raw[len(raw) // 2] ^= 1
            changed[field] = base64.b64encode(raw).decode("ascii")
            with self.subTest(field=field):
                self.assertFalse(verify_signed_file(json.dumps(changed), self.public))

    def test_wrong_public_key(self):
        self.assertFalse(verify_signed_file(self.serialized, self.other_public))

    def test_one_byte_of_public_modulus_changed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "public.json"
            export_public_key(self.public, path)
            data = json.loads(path.read_text())
            raw = bytearray(base64.b64decode(data["n"]))
            raw[len(raw) // 2] ^= 1  # mantém tamanho e paridade válidos
            data["n"] = base64.b64encode(raw).decode("ascii")
            path.write_text(json.dumps(data))
            changed_key = import_public_key(path)
            self.assertFalse(verify_signed_file(self.serialized, changed_key))

    def test_malformed_structures(self):
        cases = ["{", "[]", "null", '{"format":1,"format":2}']
        for field in self.structure:
            changed = dict(self.structure)
            del changed[field]
            cases.append(json.dumps(changed))
        for field, value in (("extra", 1), ("algorithm", "RSA"), ("hash", "SHA256"),
                             ("mgf", "MGF1-SHA256"), ("salt_length", 32.0),
                             ("format", "v2"), ("signature_b64", ""),
                             ("signature_b64", "%%%"), ("content_b64", None),
                             ("content_b64", "Zh==")):
            cases.append(json.dumps(dict(self.structure, **{field: value})))
        for value in cases:
            with self.subTest(value=value):
                with self.assertRaises(SignedFileError):
                    parse_signed_file(value)
                self.assertFalse(verify_signed_file(value, self.public))

    def test_bad_signature_encodings_and_lengths(self):
        for value in (None, 1, "á", "%%%", self.signature + "\n", "", "AA==",
                      base64.b64encode(b"\0" * 257).decode()):
            with self.subTest(value=value):
                self.assertFalse(rsa_pss_verify(self.public, self.content, value))

    def test_signature_representative_out_of_range(self):
        for value in (self.public["n"], (1 << 2048) - 1):
            signature = base64.b64encode(i2osp(value, 256)).decode()
            self.assertFalse(rsa_pss_verify(self.public, self.content, signature))

    def test_invalid_public_parameters(self):
        for field, value in (("n", 0), ("n", 17), ("n", self.public["n"] - 1),
                             ("e", 1), ("e", 4), ("e", self.public["n"]),
                             ("key_size_bits", 2047), ("key_size_bits", "2048")):
            with self.subTest(field=field, value=value):
                self.assertFalse(rsa_pss_verify(dict(self.public, **{field: value}), self.content, self.signature))
        self.assertFalse(rsa_pss_verify({}, self.content, self.signature))

    def test_public_key_parser(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "public.json"
            export_public_key(self.public, path)
            valid = json.loads(path.read_text())
            self.assertEqual(import_public_key(path), self.public)
            cases = ["[]", "null", "{", '{"n":1,"n":2}']
            for field, value in (("n", valid["n"] + "!"), ("e", ""),
                                 ("algorithm", "Ed25519"), ("key_size_bits", 2047)):
                cases.append(json.dumps(dict(valid, **{field: value})))
            for value in cases:
                with self.subTest(value=value):
                    path.write_text(value)
                    with self.assertRaises(KeyFormatError):
                        import_public_key(path)

    def test_pss_encoding_checks(self):
        # Constrói assinaturas com blocos EMSA inválidos usando a chave de teste.
        s = int.from_bytes(base64.b64decode(self.signature), "big")
        original = bytearray(i2osp(mod_exp(s, self.public["e"], self.public["n"]), 256))
        cases = []
        trailer = original.copy()
        trailer[-1] = 0
        cases.append(trailer)
        high_bit = bytearray(256)
        high_bit[0], high_bit[-1] = 0x80, 0xbc
        cases.append(high_bit)
        for index in (1, 190):  # PS e delimitador 0x01
            altered = original.copy()
            altered[index] ^= 1
            cases.append(altered)
        for encoded in cases:
            sig = mod_exp(int.from_bytes(encoded, "big"), self.private["d"], self.private["n"])
            self.assertFalse(rsa_pss_verify(self.public, self.content, base64.b64encode(i2osp(sig, 256)).decode()))

    def test_probabilistic_signatures(self):
        second = rsa_pss_sign(self.private, self.content)
        self.assertNotEqual(self.signature, second)
        self.assertTrue(rsa_pss_verify(self.public, self.content, second))

    def test_cli_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory, contextlib.redirect_stdout(io.StringIO()) as output:
            public = Path(directory) / "public.json"
            signed = Path(directory) / "signed.json"
            export_public_key(self.public, public)
            signed.write_text(self.serialized)
            args = ["verify", str(signed), str(public)]
            self.assertEqual(main(args), 0)
            self.assertIn("Arquivo íntegro", output.getvalue())
            signed.write_text(json.dumps(dict(self.structure, content_b64="AA==")))
            self.assertEqual(main(args), 1)
            public.write_text("null")
            self.assertEqual(main(args), 2)


class NonByteAlignedTests(unittest.TestCase):
    def test_2049_bit_key_and_encoded_message_overflow(self):
        public, private = generate_keypair(2049)
        content = b"Modulo sem alinhamento em bytes"
        signature = rsa_pss_sign(private, content)
        self.assertEqual(len(base64.b64decode(signature)), 257)
        self.assertTrue(rsa_pss_verify(public, content, signature))
        # n-1 cabe em k=257 bytes, mas não no emLen=256 do PSS.
        representative = mod_exp(public["n"] - 1, private["d"], public["n"])
        invalid = base64.b64encode(i2osp(representative, 257)).decode()
        self.assertFalse(rsa_pss_verify(public, content, invalid))
