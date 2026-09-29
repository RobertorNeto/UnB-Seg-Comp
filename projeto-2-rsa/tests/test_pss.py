import unittest

from rsaseg import pss
from rsaseg.aritmetica import i2osp
from rsaseg.hashing import sha3_256

from .util import chave, inverter_byte


class TestPSS(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv = chave()
        cls.pub = cls.priv.publica()

    def test_assinar_verificar(self):
        s = pss.assinar(self.priv, b"documento")
        self.assertEqual(len(s), 256)
        self.assertTrue(pss.verificar(self.pub, b"documento", s))
        self.assertFalse(pss.verificar(self.pub, b"documentO", s))

    def test_probabilistico(self):
        s1, s2 = pss.assinar(self.priv, b"x"), pss.assinar(self.priv, b"x")
        self.assertNotEqual(s1, s2)
        self.assertTrue(pss.verificar(self.pub, b"x", s1) and pss.verificar(self.pub, b"x", s2))

    def test_codificacao(self):
        m_hash = sha3_256(b"abc")
        em = pss.codificar_pss(m_hash, 2047, 32, salt=b"\x22" * 32)
        self.assertEqual(len(em), 256)
        self.assertEqual(em[-1], 0xBC)
        self.assertEqual(em[0] & 0x80, 0)  # bit mais à esquerda zerado (emBits = 2047)
        self.assertTrue(pss.verificar_codificacao_pss(m_hash, em, 2047, 32))
        self.assertFalse(pss.verificar_codificacao_pss(m_hash, em[:-1] + b"\xbd", 2047, 32))
        self.assertFalse(pss.verificar_codificacao_pss(m_hash, bytes([em[0] | 0x80]) + em[1:], 2047, 32))
        self.assertFalse(pss.verificar_codificacao_pss(m_hash, em, 2047, 20))

    def test_salt_zero(self):
        s = pss.assinar(self.priv, b"det", salt_len=0)
        self.assertEqual(s, pss.assinar(self.priv, b"det", salt_len=0))  # sem salt é determinístico
        self.assertTrue(pss.verificar(self.pub, b"det", s, salt_len=0))

    def test_assinatura_adulterada(self):
        s = pss.assinar(self.priv, b"contrato")
        for pos in (0, 1, 100, 200, 255):
            self.assertFalse(pss.verificar(self.pub, b"contrato", inverter_byte(s, pos)))

    def test_entradas_invalidas(self):
        s = pss.assinar(self.priv, b"m")
        for ruim in (b"", s[:-1], s + b"\x00", i2osp(self.pub.n, 256), b"\xff" * 256, b"\x00" * 256, "str"):
            self.assertFalse(pss.verificar(self.pub, b"m", ruim))

    def test_chave_publica_errada(self):
        s = pss.assinar(self.priv, b"m")
        self.assertFalse(pss.verificar(chave("bob").publica(), b"m", s))

    def test_nao_e_cifragem_do_hash(self):
        """A assinatura NÃO é hash^d mod n (abordagem simplificada proibida)."""
        from rsaseg.aritmetica import os2ip
        from rsaseg.primitivas import rsavp1
        s = pss.assinar(self.priv, b"m")
        em = i2osp(rsavp1(self.pub, os2ip(s)), 256)
        self.assertNotEqual(em[-32:], sha3_256(b"m"))
        self.assertEqual(em[-1], 0xBC)


if __name__ == "__main__":
    unittest.main()
