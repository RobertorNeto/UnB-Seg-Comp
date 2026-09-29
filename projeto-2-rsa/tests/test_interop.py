"""Teste ADICIONAL de interoperabilidade (restrição 3 do enunciado).

As bibliotecas consolidadas são usadas SOMENTE aqui, para conferir que a
nossa implementação produz/aceita saídas compatíveis:

  * ``cryptography`` (OpenSSL)  -> RSA-PSS com SHA3-256.
    (o backend OpenSSL do ``cryptography`` não aceita SHA3 no OAEP)
  * ``pycryptodome``            -> RSA-OAEP e RSA-PSS com SHA3-256.

Se uma biblioteca não estiver instalada, os testes correspondentes são pulados.
"""

import unittest

from rsaseg import oaep, pss

from .util import chave

try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa
    TEM_LIB = True
except ImportError:  # pragma: no cover
    TEM_LIB = False

try:
    from Crypto.Cipher import PKCS1_OAEP
    from Crypto.Hash import SHA3_256 as PC_SHA3_256
    from Crypto.PublicKey import RSA as PC_RSA
    from Crypto.Signature import pss as pc_pss
    TEM_PYCRYPTODOME = True
except ImportError:  # pragma: no cover
    TEM_PYCRYPTODOME = False


@unittest.skipUnless(TEM_LIB, "biblioteca 'cryptography' não instalada")
class TestInteroperabilidade(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        k = chave()
        cls.nosso_priv, cls.nosso_pub = k, k.publica()
        pubnum = rsa.RSAPublicNumbers(k.e, k.n)
        cls.lib_priv = rsa.RSAPrivateNumbers(k.p, k.q, k.d, k.dp, k.dq, k.qinv, pubnum).private_key()
        cls.lib_pub = pubnum.public_key()

    @staticmethod
    def _pss():
        return padding.PSS(mgf=padding.MGF1(hashes.SHA3_256()), salt_length=32)

    def test_pss_nosso_assina_lib_verifica(self):
        msg = b"arquivo a ser assinado" * 100
        s = pss.assinar(self.nosso_priv, msg)
        self.lib_pub.verify(s, msg, self._pss(), hashes.SHA3_256())  # lança exceção se inválida

    def test_pss_lib_assina_nosso_verifica(self):
        msg = b"assinado pela biblioteca"
        s = self.lib_priv.sign(msg, self._pss(), hashes.SHA3_256())
        self.assertTrue(pss.verificar(self.nosso_pub, msg, s))
        self.assertFalse(pss.verificar(self.nosso_pub, msg + b"!", s))


@unittest.skipUnless(TEM_PYCRYPTODOME, "biblioteca 'pycryptodome' não instalada")
class TestInteroperabilidadePyCryptodome(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        k = chave()
        cls.nosso_priv, cls.nosso_pub = k, k.publica()
        cls.lib_priv = PC_RSA.construct((k.n, k.e, k.d, k.p, k.q))
        cls.lib_pub = cls.lib_priv.publickey()

    def test_oaep_nosso_cifra_lib_decifra(self):
        for msg, rot in ((b"interop", b""), (b"", b""), (b"x" * 190, b"rotulo")):
            c = oaep.cifrar(self.nosso_pub, msg, rot)
            dec = PKCS1_OAEP.new(self.lib_priv, hashAlgo=PC_SHA3_256, label=rot)
            self.assertEqual(dec.decrypt(c), msg)

    def test_oaep_lib_cifra_nosso_decifra(self):
        for msg, rot in ((b"interop", b""), (b"y" * 190, b"rotulo")):
            c = PKCS1_OAEP.new(self.lib_pub, hashAlgo=PC_SHA3_256, label=rot).encrypt(msg)
            self.assertEqual(oaep.decifrar(self.nosso_priv, c, rot), msg)

    def test_pss_nos_dois_sentidos(self):
        msg = b"documento"
        s = pss.assinar(self.nosso_priv, msg)
        pc_pss.new(self.lib_pub, salt_bytes=32).verify(PC_SHA3_256.new(msg), s)  # lança se inválida
        s2 = pc_pss.new(self.lib_priv, salt_bytes=32).sign(PC_SHA3_256.new(msg))
        self.assertTrue(pss.verificar(self.nosso_pub, msg, s2))


if __name__ == "__main__":
    unittest.main()
