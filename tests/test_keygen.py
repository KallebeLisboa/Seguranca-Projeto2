"""Oráculos aritméticos da biblioteca padrão usados somente nos testes."""
import math
import unittest
from unittest.mock import patch
from rsa_keygen import (mod_exp, gcd, extended_gcd, mod_inverse,
                        is_probable_prime, generate_prime, generate_keypair)


class ArithmeticTests(unittest.TestCase):
    def test_modular_exponentiation(self):
        for base in (-17, 0, 2, 12345678901234567890):
            for exponent in (0, 1, 2, 17, 65537):
                for modulus in (1, 2, 97, (1 << 127) - 1):
                    with self.subTest(base=base, exponent=exponent, modulus=modulus):
                        self.assertEqual(mod_exp(base, exponent, modulus), pow(base, exponent, modulus))

    def test_gcd_and_bezout(self):
        for a, b in ((0, 0), (0, 17), (17, 0), (54, 24), (17, 31), (2**128, 2**64)):
            g, x, y = extended_gcd(a, b)
            self.assertEqual(g, math.gcd(a, b))
            self.assertEqual(gcd(a, b), g)
            self.assertEqual(a*x + b*y, g)

    def test_inverse(self):
        for a, m in ((3, 11), (-3, 11), (65537, 3120), (1, 2)):
            inverse = mod_inverse(a, m)
            self.assertEqual(inverse, pow(a, -1, m))
            self.assertEqual(a * inverse % m, 1)
        for a, m in ((0, 7), (6, 9), (2, 4)):
            with self.assertRaises(ValueError):
                mod_inverse(a, m)

    def test_invalid_arithmetic_parameters(self):
        for args in ((2, -1, 7), (2, 3, 0), (2, 3, -7), (2, 1.5, 7), (True, 2, 7)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                mod_exp(*args)
        for args in ((1, 0), (1, 1), (1, -3), (1.5, 7)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                mod_inverse(*args)


class PrimalityTests(unittest.TestCase):
    def test_small_numbers_against_trial_division(self):
        # Testemunha fixa torna a execução reproduzível; não altera a produção.
        with patch('rsa_keygen.secrets.randbelow', return_value=0):
            for n in range(-3, 1000):
                expected = n >= 2 and all(n % d for d in range(2, math.isqrt(max(n, 0)) + 1))
                self.assertEqual(is_probable_prime(n), expected, n)

    def test_strong_pseudoprime_requires_another_witness(self):
        # 1373653 = 829 * 1657 passa na base 2, mas falha na base 5.
        with patch('rsa_keygen.secrets.randbelow', return_value=0):
            self.assertTrue(is_probable_prime(1373653, rounds=1))
        with patch('rsa_keygen.secrets.randbelow', side_effect=[0, 3]):
            self.assertFalse(is_probable_prime(1373653, rounds=2))

    def test_large_prime_and_composite(self):
        with patch('rsa_keygen.secrets.randbelow', return_value=0):
            self.assertTrue(is_probable_prime((1 << 127) - 1))
            self.assertFalse(is_probable_prime(211 * 223))

    def test_invalid_rounds_and_types(self):
        for rounds in (0, -1, True, 1.5, '20'):
            for operation in (lambda: is_probable_prime(211, rounds),
                              lambda: generate_prime(8, rounds),
                              lambda: generate_keypair(miller_rabin_rounds=rounds)):
                with self.subTest(rounds=rounds), self.assertRaises(ValueError):
                    operation()
        with self.assertRaises(ValueError):
            is_probable_prime(3.5)

    def test_generated_small_prime(self):
        for bits in (8, 16):
            prime = generate_prime(bits)
            self.assertEqual(prime.bit_length(), bits)
            self.assertTrue(all(prime % d for d in range(2, math.isqrt(prime) + 1)))
        for bits in (7, 0, -1, 8.0, True):
            with self.subTest(bits=bits), self.assertRaises(ValueError):
                generate_prime(bits)


class KeyGenerationTests(unittest.TestCase):
    def test_invalid_parameters_before_random_generation(self):
        cases = [dict(key_size_bits=v) for v in (2047, -1, True, '2048', 2048.0)]
        cases += [dict(e=v) for v in (0, 1, 2, -3, True, 3.0, '3', (1 << 2048) + 1)]
        for kwargs in cases:
            with self.subTest(kwargs=kwargs), patch('rsa_keygen.generate_prime') as generate:
                with self.assertRaises(ValueError):
                    generate_keypair(**kwargs)
                generate.assert_not_called()

    def test_generated_key_relations(self):
        public, private = generate_keypair()
        n, p, q = private['n'], private['p'], private['q']
        e, d = private['e'], private['d']
        self.assertEqual(n.bit_length(), 2048)
        self.assertEqual(public, {k: private[k] for k in ('n', 'e', 'key_size_bits')})
        self.assertNotEqual(p, q)
        self.assertEqual(n, p*q)
        self.assertEqual(e*d % ((p-1)*(q-1)), 1)
        self.assertEqual(private['dp'], d % (p-1))
        self.assertEqual(private['dq'], d % (q-1))
        self.assertEqual(q*private['qinv'] % p, 1)
        for message in (0, 1, p, q, n-1, 42):
            self.assertEqual(mod_exp(mod_exp(message, e, n), d, n), message)
