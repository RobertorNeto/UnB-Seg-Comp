import dataclasses
import unittest

from rsaseg import chaves as ch
from rsaseg.aritmetica import mmc
from rsaseg.erros import ErroChave, ErroFormato, ErroParametro
from rsaseg.primos import eh_provavel_primo

from .util import chave


class TestChaves(unittest.TestCase):
    def test_parametros_gerados(self):
        k = chave()
        self.assertEqual(k.bits, 2048)
        self.assertEqual(k.p * k.q, k.n)
        self.assertTrue(eh_provavel_primo(k.p) and eh_provavel_primo(k.q))
        self.assertEqual((k.e * k.d) % mmc(k.p - 1, k.q - 1), 1)
        self.assertEqual(k.dp, k.d % (k.p - 1))
        self.assertEqual(k.dq, k.d % (k.q - 1))
        self.assertEqual((k.qinv * k.q) % k.p, 1)
        self.assertGreater(abs(k.p - k.q), 1 << (1024 - 100))
        self.assertGreater(k.d, 1 << 1024)
        k.validar()

    def test_tamanho_minimo(self):
        with self.assertRaises(ErroParametro):
            ch.gerar_par_chaves(1024)
        with self.assertRaises(ErroParametro):
            ch.gerar_par_chaves(2048, e=3)

    def test_exportar_importar(self):
        k = chave()
        pub = ch.importar_publica(ch.exportar_publica(k.publica()))
        self.assertEqual(pub, k.publica())
        priv = ch.importar_privada(ch.exportar_privada(k))
        self.assertEqual(dataclasses.astuple(priv), dataclasses.astuple(k))

    def test_repr_nao_vaza_segredo(self):
        self.assertNotIn(format(chave().d, "x"), repr(chave()))
        self.assertNotIn(str(chave().d), repr(chave()))

    def test_importacao_malformada(self):
        pub_txt = ch.exportar_publica(chave().publica())
        for ruim in ["", "lixo", pub_txt.replace("PUBLIC", "PRIVATE"),
                     pub_txt.replace("BEGIN", "BEGlN"), pub_txt[:-40] + "\n-----END RSASEG PUBLIC KEY-----"]:
            with self.assertRaises(ErroFormato):
                ch.importar_publica(ruim)
        with self.assertRaises(ErroFormato):
            ch.importar_privada(pub_txt)

    def test_hex_estrito(self):
        dados = {"formato": "rsaseg-v1", "tipo": "publica", "bits": 2048,
                 "n": "0x" + format(chave().n, "x"), "e": "10001"}
        txt = ch._envelope(ch.ROTULO_PUB, dados)
        with self.assertRaises(ErroFormato):
            ch.importar_publica(txt)

    def test_chave_privada_inconsistente(self):
        k = chave()
        ruim = dataclasses.replace(k, d=k.d + 2)
        with self.assertRaises(ErroChave):
            ch.importar_privada(ch.exportar_privada(ruim))
        ruim = dataclasses.replace(k, q=k.q + 2)
        with self.assertRaises(ErroChave):
            ch.importar_privada(ch.exportar_privada(ruim))

    def test_chave_publica_fraca(self):
        with self.assertRaises(ErroChave):
            ch.ChavePublica(chave().n, 3).validar()
        with self.assertRaises(ErroChave):
            ch.ChavePublica((1 << 1023) + 1, 65537).validar()


if __name__ == "__main__":
    unittest.main()
