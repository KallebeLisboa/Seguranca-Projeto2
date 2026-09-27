"""Biblioteca externa somente como oráculo de teste (restrição 3 do PDF)."""
import base64
import unittest

from rsa_crypto import rsa_pss_sign
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
