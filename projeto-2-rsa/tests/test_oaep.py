import unittest

from rsaseg import oaep
from rsaseg.aritmetica import i2osp
from rsaseg.erros import ErroDecifragem, MensagemMuitoLonga
from rsaseg.hashing import H_LEN, mgf1, sha3_256

from .util import chave, inverter_byte


class TestMGF1(unittest.TestCase):
    def test_tamanhos_e_prefixo(self):
        s = b"semente"
        for n in (0, 1, 31, 32, 33, 223, 1000):
            self.assertEqual(len(mgf1(s, n)), n)
        self.assertEqual(mgf1(s, 100)[:40], mgf1(s, 40))
        # definição: primeiro bloco = Hash(semente || 00000000)
        self.assertEqual(mgf1(s, 32), sha3_256(s + b"\x00\x00\x00\x00"))
        self.assertEqual(mgf1(s, 64)[32:], sha3_256(s + b"\x00\x00\x00\x01"))


class TestOAEP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv = chave()
        cls.pub = cls.priv.publica()

    def test_ida_e_volta(self):
        maximo = oaep.tamanho_maximo_mensagem(self.pub)
        self.assertEqual(maximo, 256 - 2 * H_LEN - 2)  # 190
        for msg in (b"", b"a", "Olá, mundo! ✓".encode(), bytes(range(190))[:maximo]):
            c = oaep.cifrar(self.pub, msg)
            self.assertEqual(len(c), 256)
            self.assertEqual(oaep.decifrar(self.priv, c), msg)

    def test_mensagem_longa(self):
        with self.assertRaises(MensagemMuitoLonga):
            oaep.cifrar(self.pub, b"x" * 191)

    def test_probabilistico(self):
        self.assertNotEqual(oaep.cifrar(self.pub, b"igual"), oaep.cifrar(self.pub, b"igual"))

    def test_rotulo(self):
        c = oaep.cifrar(self.pub, b"msg", b"rotulo-A")
        self.assertEqual(oaep.decifrar(self.priv, c, b"rotulo-A"), b"msg")
        with self.assertRaises(ErroDecifragem):
            oaep.decifrar(self.priv, c, b"rotulo-B")

    def test_texto_cifrado_adulterado(self):
        c = oaep.cifrar(self.pub, b"mensagem secreta")
        for pos in (0, 1, 50, 128, 200, 255):
            for mask in (0x01, 0x80):
                with self.assertRaises(ErroDecifragem):
                    oaep.decifrar(self.priv, inverter_byte(c, pos, mask))

    def test_entradas_invalidas(self):
        c = oaep.cifrar(self.pub, b"m")
        for ruim in (b"", c[:-1], c + b"\x00", i2osp(self.pub.n, 256), b"\xff" * 256, "texto"):
            with self.assertRaises(ErroDecifragem):
                oaep.decifrar(self.priv, ruim)

    def test_chave_errada(self):
        c = oaep.cifrar(self.pub, b"para alice")
        with self.assertRaises(ErroDecifragem):
            oaep.decifrar(chave("bob"), c)

    def test_mensagens_de_erro_uniformes(self):
        c = oaep.cifrar(self.pub, b"m")
        msgs = set()
        for ruim in (inverter_byte(c, 0), inverter_byte(c, 255), c[:-1], b"\xff" * 256):
            try:
                oaep.decifrar(self.priv, ruim)
            except ErroDecifragem as exc:
                msgs.add(str(exc))
        self.assertEqual(msgs, {"falha na decifragem"})

    def test_decodificacao_detecta_padding(self):
        k = 256
        em = oaep.codificar_oaep(b"abc", k, semente=b"\x11" * 32)
        self.assertEqual(oaep.decodificar_oaep(em, k), b"abc")
        with self.assertRaises(ErroDecifragem):
            oaep.decodificar_oaep(b"\x01" + em[1:], k)  # Y != 0


if __name__ == "__main__":
    unittest.main()
