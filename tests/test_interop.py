"""Biblioteca externa somente como oráculo de teste (restrição 3 do PDF)."""
import base64
import unittest

from rsa_crypto import rsa_pss_sign, rsa_oaep_encrypt, rsa_oaep_decrypt
from rsa_keygen import generate_keypair

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
except ImportError:
    rsa = None


@unittest.skipIf(rsa is None, "Opcional: instale cryptography para interoperabilidade")
class InteroperabilityTests(unittest.TestCase):
    def test_library_verifies_manual_signature(self):
        public, private = generate_keypair()
        content = b"Interoperabilidade RSA-PSS / SHA3-256"
        signature = base64.b64decode(rsa_pss_sign(private, content))
        verifier = rsa.RSAPublicNumbers(public["e"], public["n"]).public_key()
        profile = padding.PSS(mgf=padding.MGF1(hashes.SHA3_256()), salt_length=32)
        verifier.verify(signature, content, profile, hashes.SHA3_256())
        with self.assertRaises(InvalidSignature):
            verifier.verify(signature, content + b"!", profile, hashes.SHA3_256())


try:
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA3_256
    from Crypto.PublicKey import RSA
except ImportError:
    RSA = None


@unittest.skipIf(RSA is None, "Opcional: instale pycryptodome para interoperabilidade OAEP")
class OAEPInteroperabilityTests(unittest.TestCase):
    def test_library_decrypts_manual_oaep(self):
        public, private = generate_keypair()
        reference = RSA.construct((public['n'], public['e'], private['d'],
                                   private['p'], private['q']))
        label = b'interoperabilidade'
        decoder = PKCS1_OAEP.new(reference, hashAlgo=SHA3_256, label=label)
        for message in (b'', b'OAEP manual', bytes(range(190))):
            ciphertext = rsa_oaep_encrypt(public, message, label)
            self.assertEqual(decoder.decrypt(ciphertext), message)
            self.assertEqual(rsa_oaep_decrypt(private, ciphertext, label), message)
        altered = bytearray(ciphertext)
        altered[100] ^= 1
        with self.assertRaises(ValueError):
            decoder.decrypt(bytes(altered))
        with self.assertRaises(ValueError):
            rsa_oaep_decrypt(private, bytes(altered), label)
