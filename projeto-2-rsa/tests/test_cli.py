import contextlib
import io
import os
import tempfile
import unittest

from rsaseg import chaves as ch
from rsaseg.cli import main

from .util import chave


def rodar(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        codigo = main(list(args))
    return codigo, out.getvalue(), err.getvalue()


class TestCLI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.d = tempfile.TemporaryDirectory()
        base = os.path.join(cls.d.name, "alice")
        k = chave()
        ch.salvar_texto(base + ".priv", ch.exportar_privada(k), privado=True)
        ch.salvar_texto(base + ".pub", ch.exportar_publica(k.publica()))
        cls.pub, cls.priv = base + ".pub", base + ".priv"
        cls.doc = os.path.join(cls.d.name, "doc.txt")
        with open(cls.doc, "w") as f:
            f.write("conteúdo do documento\n")

    @classmethod
    def tearDownClass(cls):
        cls.d.cleanup()

    def test_permissao_chave_privada(self):
        if os.name == "posix":
            self.assertEqual(os.stat(self.priv).st_mode & 0o777, 0o600)

    def test_cifrar_decifrar(self):
        enc = os.path.join(self.d.name, "m.enc")
        self.assertEqual(rodar("cifrar", "--chave", self.pub, "--mensagem", "olá", "--saida", enc)[0], 0)
        codigo, out, _ = rodar("decifrar", "--chave", self.priv, "--entrada", enc)
        self.assertEqual((codigo, out.strip()), (0, "olá"))
        with open(enc, "w") as f:
            f.write("AAAA\n")
        self.assertEqual(rodar("decifrar", "--chave", self.priv, "--entrada", enc)[0], 1)

    def test_assinar_verificar(self):
        self.assertEqual(rodar("assinar", "--chave", self.priv, "--arquivo", self.doc)[0], 0)
        codigo, out, _ = rodar("verificar", "--chave", self.pub, "--arquivo", self.doc, "--assinatura", self.doc + ".sig")
        self.assertEqual(codigo, 0, out)
        self.assertIn("VÁLIDA", out)
        with open(self.doc, "a") as f:
            f.write("x")
        codigo, out, _ = rodar("verificar", "--chave", self.pub, "--arquivo", self.doc, "--assinatura", self.doc + ".sig")
        self.assertEqual(codigo, 1)
        self.assertIn("modificado", out)

    def test_entrada_invalida(self):
        self.assertEqual(rodar("info", "--chave", "/nao/existe")[0], 2)
        lixo = os.path.join(self.d.name, "lixo.pub")
        with open(lixo, "w") as f:
            f.write("nada")
        self.assertEqual(rodar("cifrar", "--chave", lixo, "--mensagem", "a")[0], 2)
        self.assertEqual(rodar("cifrar", "--chave", self.pub, "--mensagem", "a" * 191)[0], 2)

    def test_info(self):
        codigo, out, _ = rodar("info", "--chave", self.priv)
        self.assertEqual(codigo, 0)
        self.assertIn("Bits: 2048", out)


if __name__ == "__main__":
    unittest.main()
