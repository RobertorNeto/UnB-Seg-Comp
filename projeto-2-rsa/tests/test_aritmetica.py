import secrets
import unittest

from rsaseg.aritmetica import (euclides_estendido, exp_modular, i2osp, inverso_modular,
                               mdc, mmc, os2ip, xor_bytes)
from rsaseg.erros import ErroParametro


class TestAritmetica(unittest.TestCase):
    def test_exp_modular_contra_pow(self):
        for _ in range(50):
            m = secrets.randbits(512) | 1
            b, e = secrets.randbits(600), secrets.randbits(512)
            self.assertEqual(exp_modular(b, e, m), pow(b, e, m))
        self.assertEqual(exp_modular(5, 0, 7), 1)
        self.assertEqual(exp_modular(5, 3, 1), 0)

    def test_exp_modular_invalidos(self):
        with self.assertRaises(ErroParametro):
            exp_modular(2, -1, 7)
        with self.assertRaises(ErroParametro):
            exp_modular(2, 3, 0)

    def test_euclides_e_inverso(self):
        for _ in range(50):
            a, b = secrets.randbits(256) + 1, secrets.randbits(256) + 1
            g, x, y = euclides_estendido(a, b)
            self.assertEqual(a * x + b * y, g)
            self.assertEqual(g, mdc(a, b))
        m = (1 << 127) - 1  # primo de Mersenne
        for _ in range(20):
            a = secrets.randbelow(m - 1) + 1
            self.assertEqual(inverso_modular(a, m), pow(a, -1, m))
        with self.assertRaises(ErroParametro):
            inverso_modular(6, 9)
        self.assertEqual(mmc(4, 6), 12)

    def test_i2osp_os2ip(self):
        self.assertEqual(i2osp(0x0102, 4), b"\x00\x00\x01\x02")
        self.assertEqual(os2ip(b"\x00\x00\x01\x02"), 0x0102)
        with self.assertRaises(ErroParametro):
            i2osp(256, 1)
        with self.assertRaises(ErroParametro):
            i2osp(-1, 4)
        x = secrets.randbits(2048)
        self.assertEqual(os2ip(i2osp(x, 256)), x)

    def test_xor(self):
        self.assertEqual(xor_bytes(b"\x0f\xf0", b"\xff\xff"), b"\xf0\x0f")
        self.assertEqual(xor_bytes(b"\x00\x01", b"\x00\x00"), b"\x00\x01")  # zeros à esquerda preservados
        with self.assertRaises(ErroParametro):
            xor_bytes(b"a", b"ab")


if __name__ == "__main__":
    unittest.main()
