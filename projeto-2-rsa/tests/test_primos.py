import unittest

from rsaseg.erros import ErroParametro
from rsaseg.primos import eh_provavel_primo, gerar_primo, nucleo_miller_rabin

PRIMOS = [2, 3, 5, 7, 13, 7919, 104729, 2**31 - 1, 2**61 - 1, 2**89 - 1,
          2**127 - 1, 2**521 - 1, 2**607 - 1]
# Números de Carmichael: enganam o teste de Fermat para toda base coprima.
CARMICHAEL = [561, 1105, 1729, 2465, 2821, 6601, 8911, 41041, 825265, 321197185,
              5394826801, 232250619601, 9746347772161]
# Pseudoprimos fortes: 2047 (base 2), 3215031751 (bases 2, 3, 5, 7).
PSEUDOPRIMOS_FORTES = [2047, 1373653, 25326001, 3215031751, 3825123056546413051]


class TestMillerRabin(unittest.TestCase):
    def test_primos_conhecidos(self):
        for p in PRIMOS:
            self.assertTrue(eh_provavel_primo(p), p)
            if p > 3:
                self.assertTrue(nucleo_miller_rabin(p), p)

    def test_compostos(self):
        for n in [0, 1, 4, 9, 15, 1000, (2**61 - 1) * (2**89 - 1), (2**521 - 1) * (2**607 - 1)]:
            self.assertFalse(eh_provavel_primo(n), n)

    def test_carmichael_no_nucleo(self):
        # Testa o Miller-Rabin SEM a divisão por tentativa.
        for n in CARMICHAEL:
            self.assertFalse(nucleo_miller_rabin(n), n)

    def test_pseudoprimos_fortes(self):
        for n in PSEUDOPRIMOS_FORTES:
            self.assertFalse(nucleo_miller_rabin(n), n)

    def test_entrada_invalida(self):
        with self.assertRaises(ErroParametro):
            eh_provavel_primo(7.0)
        with self.assertRaises(ErroParametro):
            nucleo_miller_rabin(7, rodadas=0)

    def test_gerar_primo(self):
        for bits in (64, 256, 1024):
            p = gerar_primo(bits, e=65537)
            self.assertEqual(p.bit_length(), bits)
            self.assertEqual(p >> (bits - 2), 0b11)  # dois bits mais altos ligados
            self.assertEqual(p % 2, 1)
            self.assertNotEqual((p - 1) % 65537, 0)
            self.assertTrue(eh_provavel_primo(p))


if __name__ == "__main__":
    unittest.main()
