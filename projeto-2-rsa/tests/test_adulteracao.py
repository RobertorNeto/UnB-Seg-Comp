"""Parte IV — testes de integridade exigidos no enunciado:
(a) um byte do arquivo; (b) um byte da assinatura; (c) a chave pública."""

import base64
import os
import tempfile
import unittest

from rsaseg import chaves as ch
from rsaseg.assinatura_arquivo import Status, analisar, assinar_arquivo, verificar_arquivo
from rsaseg.erros import ErroChave, ErroFormato

from .util import chave, inverter_byte


class TestAdulteracao(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.priv = chave()
        cls.pub = cls.priv.publica()
        cls.dir = tempfile.TemporaryDirectory()
        cls.arquivo = os.path.join(cls.dir.name, "contrato.txt")
        cls.conteudo = ("CONTRATO DE PRESTAÇÃO DE SERVIÇOS\n" * 200).encode()
        with open(cls.arquivo, "wb") as f:
            f.write(cls.conteudo)
        cls.sig_txt = assinar_arquivo(cls.priv, cls.arquivo).serializar()

    @classmethod
    def tearDownClass(cls):
        cls.dir.cleanup()

    def _escrever(self, nome, dados):
        caminho = os.path.join(self.dir.name, nome)
        with open(caminho, "wb") as f:
            f.write(dados)
        return caminho

    def test_arquivo_integro(self):
        r = verificar_arquivo(self.pub, self.arquivo, self.sig_txt)
        self.assertTrue(r.valida, str(r))
        self.assertIs(r.status, Status.VALIDA)

    def test_parsing_da_estrutura(self):
        s = analisar(self.sig_txt)
        self.assertEqual(s.salt_len, 32)
        self.assertEqual(s.bits_chave, 2048)
        self.assertEqual(s.nome_arquivo, "contrato.txt")
        self.assertEqual(s.tamanho_arquivo, len(self.conteudo))
        self.assertEqual(len(s.assinatura), 256)
        self.assertEqual(s.impressao_digital, self.pub.impressao_digital())

    # (a) um byte do arquivo -------------------------------------------------
    def test_a_um_byte_do_arquivo(self):
        for pos in (0, len(self.conteudo) // 2, len(self.conteudo) - 1):
            caminho = self._escrever("contrato.txt", inverter_byte(self.conteudo, pos))
            try:
                r = verificar_arquivo(self.pub, caminho, self.sig_txt)
                self.assertFalse(r.valida)
                self.assertIs(r.status, Status.ARQUIVO_ALTERADO)
            finally:
                self._escrever("contrato.txt", self.conteudo)

    def test_a_byte_acrescentado(self):
        caminho = self._escrever("contrato2.txt", self.conteudo + b"\n")
        self.assertIs(verificar_arquivo(self.pub, caminho, self.sig_txt).status, Status.ARQUIVO_ALTERADO)

    def test_a_digest_do_cabecalho_forjado_nao_engana(self):
        """Atacante altera o arquivo E atualiza File-Digest/File-Size: continua inválido."""
        from rsaseg.hashing import sha3_256
        novo = inverter_byte(self.conteudo, 10)
        caminho = self._escrever("contrato3.txt", novo)
        s = analisar(self.sig_txt)
        s.digest, s.tamanho_arquivo = sha3_256(novo), len(novo)
        r = verificar_arquivo(self.pub, caminho, s.serializar())
        self.assertFalse(r.valida)

    # (b) um byte da assinatura ----------------------------------------------
    def test_b_um_byte_da_assinatura(self):
        s = analisar(self.sig_txt)
        original = s.assinatura
        for pos in (0, 1, 127, 254, 255):
            s.assinatura = inverter_byte(original, pos)
            r = verificar_arquivo(self.pub, self.arquivo, s.serializar())
            self.assertFalse(r.valida)
            self.assertIs(r.status, Status.ASSINATURA_INVALIDA)

    def test_b_caractere_base64(self):
        linhas = self.sig_txt.splitlines()
        idx = linhas.index("Signature:") + 1
        c = linhas[idx][5]
        linhas[idx] = linhas[idx][:5] + ("A" if c != "A" else "B") + linhas[idx][6:]
        r = verificar_arquivo(self.pub, self.arquivo, "\n".join(linhas))
        self.assertFalse(r.valida)

    def test_b_assinatura_truncada(self):
        s = analisar(self.sig_txt)
        s.assinatura = s.assinatura[:-1]
        self.assertIs(verificar_arquivo(self.pub, self.arquivo, s.serializar()).status, Status.ASSINATURA_INVALIDA)

    # (c) a chave pública -----------------------------------------------------
    def test_c_outra_chave_publica(self):
        r = verificar_arquivo(chave("bob").publica(), self.arquivo, self.sig_txt)
        self.assertFalse(r.valida)
        self.assertIs(r.status, Status.CHAVE_INCORRETA)

    def test_c_um_byte_do_modulo(self):
        k = self.pub.k
        n_bytes = bytearray(self.pub.n.to_bytes(k, "big"))
        for pos in (k - 1, k // 2, 5):
            b = bytearray(n_bytes)
            b[pos] ^= 0x04
            adulterada = ch.ChavePublica(int.from_bytes(b, "big"), self.pub.e)
            r = verificar_arquivo(adulterada, self.arquivo, self.sig_txt)
            self.assertFalse(r.valida)

    def test_c_um_byte_do_arquivo_de_chave(self):
        """Altera um caractere do arquivo .pub exportado: ou a importação falha, ou a verificação."""
        txt = ch.exportar_publica(self.pub)
        linhas = txt.splitlines()
        for i in (1, 2, len(linhas) - 2):
            l = list(linhas[i])
            l[10] = "A" if l[10] != "A" else "B"
            mod = "\n".join(linhas[:i] + ["".join(l)] + linhas[i + 1 :])
            try:
                pub = ch.importar_publica(mod)
            except (ErroFormato, ErroChave):
                continue
            self.assertFalse(verificar_arquivo(pub, self.arquivo, self.sig_txt).valida)

    def test_c_expoente_alterado(self):
        r = verificar_arquivo(ch.ChavePublica(self.pub.n, 65539), self.arquivo, self.sig_txt)
        self.assertFalse(r.valida)

    # Estrutura malformada ----------------------------------------------------
    def test_estrutura_malformada(self):
        casos = [
            "",
            "lixo",
            self.sig_txt.replace("Hash: SHA3-256", "Hash: SHA-1"),
            self.sig_txt.replace("Algorithm: RSASSA-PSS", "Algorithm: RSA-PKCS1v15"),
            self.sig_txt.replace("Salt-Length: 32", "Salt-Length: 0"),
            self.sig_txt.replace("Salt-Length: 32", "Salt-Length: -1"),
            self.sig_txt.replace("Version: 1\n", ""),
            self.sig_txt.replace("Version: 1\n", "Version: 1\nVersion: 1\n"),
            self.sig_txt.replace("Signature:\n", "Signature:\n!!"),
            self.sig_txt.replace("-----END RSASEG SIGNATURE-----", ""),
            self.sig_txt.replace("File-Size:", "Extra: x\nFile-Size:"),
        ]
        for txt in casos:
            r = verificar_arquivo(self.pub, self.arquivo, txt)
            self.assertFalse(r.valida)
            self.assertIs(r.status, Status.ESTRUTURA_INVALIDA, txt[:60])

    def test_arquivo_vazio(self):
        caminho = self._escrever("vazio.bin", b"")
        sig = assinar_arquivo(self.priv, caminho).serializar()
        self.assertTrue(verificar_arquivo(self.pub, caminho, sig).valida)
        caminho = self._escrever("vazio.bin", b"\x00")
        self.assertFalse(verificar_arquivo(self.pub, caminho, sig).valida)

    def test_arquivo_grande(self):
        dados = os.urandom(3 * 1024 * 1024 + 7)
        caminho = self._escrever("grande.bin", dados)
        sig = assinar_arquivo(self.priv, caminho).serializar()
        self.assertTrue(verificar_arquivo(self.pub, caminho, sig).valida)
        self._escrever("grande.bin", inverter_byte(dados, 2 * 1024 * 1024))
        self.assertFalse(verificar_arquivo(self.pub, caminho, sig).valida)

    def test_base64_da_assinatura(self):
        s = analisar(self.sig_txt)
        b64 = "".join(self.sig_txt.split("Signature:\n")[1].splitlines()[:-1])
        self.assertEqual(base64.b64decode(b64), s.assinatura)


if __name__ == "__main__":
    unittest.main()
