"""Assinatura destacada (detached) de arquivos e verificação de integridade.

Formato do arquivo ``.sig`` (ver docs/formatos.md):

    -----BEGIN RSASEG SIGNATURE-----
    Version: 1
    Algorithm: RSASSA-PSS
    Hash: SHA3-256
    MGF: MGF1-SHA3-256
    Salt-Length: 32
    Key-Bits: 2048
    Key-Fingerprint: <SHA3-256 hex da chave pública>
    File-Name: relatorio.pdf
    File-Size: 12345
    File-Digest: <SHA3-256 hex do arquivo>
    Signature:
    <assinatura RSA-PSS em Base64, linhas de 64 caracteres>
    -----END RSASEG SIGNATURE-----

Segurança: os campos de cabeçalho NÃO são confiáveis — a decisão de
validade é tomada exclusivamente pela verificação RSA-PSS sobre o digest
RECALCULADO do arquivo. Os metadados servem apenas para diagnóstico.
"""

import base64
import binascii
import os
import re
from dataclasses import dataclass, field
from enum import Enum

from .chaves import ChavePrivada, ChavePublica
from .erros import ErroFormato, ErroParametro
from .hashing import NOME_HASH, NOME_MGF, sha3_256_arquivo
from .pss import SALT_LEN_PADRAO, assinar_digest, verificar_digest

ROTULO = "RSASEG SIGNATURE"
VERSAO = "1"
ALGORITMO = "RSASSA-PSS"
_CAMPOS = ("Version", "Algorithm", "Hash", "MGF", "Salt-Length", "Key-Bits",
           "Key-Fingerprint", "File-Name", "File-Size", "File-Digest")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_DEC = re.compile(r"^(0|[1-9][0-9]{0,19})$")


@dataclass
class AssinaturaArquivo:
    salt_len: int
    bits_chave: int
    impressao_digital: str
    nome_arquivo: str
    tamanho_arquivo: int
    digest: bytes
    assinatura: bytes

    def serializar(self) -> str:
        b64 = base64.b64encode(self.assinatura).decode("ascii")
        linhas = [
            f"-----BEGIN {ROTULO}-----",
            f"Version: {VERSAO}",
            f"Algorithm: {ALGORITMO}",
            f"Hash: {NOME_HASH}",
            f"MGF: {NOME_MGF}",
            f"Salt-Length: {self.salt_len}",
            f"Key-Bits: {self.bits_chave}",
            f"Key-Fingerprint: {self.impressao_digital}",
            f"File-Name: {self.nome_arquivo}",
            f"File-Size: {self.tamanho_arquivo}",
            f"File-Digest: {self.digest.hex()}",
            "Signature:",
            *[b64[i : i + 64] for i in range(0, len(b64), 64)],
            f"-----END {ROTULO}-----",
        ]
        return "\n".join(linhas) + "\n"


def _nome_seguro(caminho) -> str:
    nome = os.path.basename(os.fspath(caminho))
    if not nome or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in nome):
        raise ErroParametro("nome de arquivo inválido para a estrutura de assinatura")
    return nome


def assinar_arquivo(chave: ChavePrivada, caminho) -> AssinaturaArquivo:
    """Calcula SHA3-256 do arquivo e assina com RSA-PSS."""
    digest = sha3_256_arquivo(caminho)
    assinatura = assinar_digest(chave, digest, SALT_LEN_PADRAO)
    return AssinaturaArquivo(
        salt_len=SALT_LEN_PADRAO,
        bits_chave=chave.bits,
        impressao_digital=chave.publica().impressao_digital(),
        nome_arquivo=_nome_seguro(caminho),
        tamanho_arquivo=os.path.getsize(caminho),
        digest=digest,
        assinatura=assinatura,
    )


def analisar(texto: str) -> AssinaturaArquivo:
    """Parsing estrito da estrutura assinada. Qualquer desvio -> ErroFormato."""
    if not isinstance(texto, str):
        raise ErroFormato("estrutura de assinatura deve ser texto")
    linhas = [l.rstrip("\r") for l in texto.strip().split("\n")]
    if len(linhas) < 4 or linhas[0] != f"-----BEGIN {ROTULO}-----" or linhas[-1] != f"-----END {ROTULO}-----":
        raise ErroFormato("delimitadores BEGIN/END ausentes ou incorretos")

    campos, i = {}, 1
    while i < len(linhas) - 1 and linhas[i] != "Signature:":
        linha = linhas[i]
        if ": " not in linha:
            raise ErroFormato(f"linha de cabeçalho malformada: {linha[:40]!r}")
        chave, valor = linha.split(": ", 1)
        if chave not in _CAMPOS:
            raise ErroFormato(f"campo desconhecido: {chave[:40]!r}")
        if chave in campos:
            raise ErroFormato(f"campo duplicado: {chave}")
        campos[chave] = valor
        i += 1
    if i >= len(linhas) - 1:
        raise ErroFormato("seção 'Signature:' ausente")
    faltando = set(_CAMPOS) - set(campos)
    if faltando:
        raise ErroFormato(f"campos ausentes: {', '.join(sorted(faltando))}")

    # Parâmetros fixos: só aceitamos exatamente o que implementamos.
    esperados = {"Version": VERSAO, "Algorithm": ALGORITMO, "Hash": NOME_HASH, "MGF": NOME_MGF}
    for k, v in esperados.items():
        if campos[k] != v:
            raise ErroFormato(f"valor não suportado em {k}: {campos[k][:40]!r}")
    for k in ("Salt-Length", "Key-Bits", "File-Size"):
        if not _DEC.match(campos[k]):
            raise ErroFormato(f"{k} deve ser inteiro decimal não negativo")
    if not _HEX64.match(campos["File-Digest"]) or not _HEX64.match(campos["Key-Fingerprint"]):
        raise ErroFormato("File-Digest/Key-Fingerprint devem ter 64 dígitos hexadecimais minúsculos")

    b64 = "".join(l.strip() for l in linhas[i + 1 : -1])
    if not b64:
        raise ErroFormato("assinatura vazia")
    try:
        assinatura = base64.b64decode(b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ErroFormato("assinatura não é Base64 válido") from exc

    return AssinaturaArquivo(
        salt_len=int(campos["Salt-Length"]),
        bits_chave=int(campos["Key-Bits"]),
        impressao_digital=campos["Key-Fingerprint"],
        nome_arquivo=campos["File-Name"],
        tamanho_arquivo=int(campos["File-Size"]),
        digest=bytes.fromhex(campos["File-Digest"]),
        assinatura=assinatura,
    )


class Status(Enum):
    VALIDA = "ASSINATURA VÁLIDA — arquivo íntegro e autêntico"
    ARQUIVO_ALTERADO = "ASSINATURA INVÁLIDA — o arquivo foi modificado após a assinatura"
    CHAVE_INCORRETA = "ASSINATURA INVÁLIDA — a chave pública não corresponde à do signatário"
    ASSINATURA_INVALIDA = "ASSINATURA INVÁLIDA — a assinatura foi corrompida ou forjada"
    ESTRUTURA_INVALIDA = "ASSINATURA INVÁLIDA — estrutura assinada malformada"


@dataclass
class ResultadoVerificacao:
    status: Status
    detalhes: list = field(default_factory=list)

    @property
    def valida(self) -> bool:
        return self.status is Status.VALIDA

    def __str__(self) -> str:
        return "\n".join([self.status.value] + [f"  - {d}" for d in self.detalhes])


def verificar_arquivo(chave: ChavePublica, caminho_arquivo, texto_assinatura: str) -> ResultadoVerificacao:
    """Parsing + recálculo do digest + verificação RSA-PSS + diagnóstico."""
    try:
        sig = analisar(texto_assinatura)
    except ErroFormato as exc:
        return ResultadoVerificacao(Status.ESTRUTURA_INVALIDA, [str(exc)])

    detalhes = []
    digest_atual = sha3_256_arquivo(caminho_arquivo)

    # Política: o verificador não negocia parâmetros vindos do arquivo.
    if sig.salt_len != SALT_LEN_PADRAO:
        return ResultadoVerificacao(Status.ESTRUTURA_INVALIDA, [f"Salt-Length {sig.salt_len} não aceito (esperado {SALT_LEN_PADRAO})"])

    # DECISÃO: somente a verificação criptográfica sobre o digest recalculado.
    ok = verificar_digest(chave, digest_atual, sig.assinatura, SALT_LEN_PADRAO)

    fp = chave.impressao_digital()
    if ok:
        if sig.nome_arquivo != os.path.basename(os.fspath(caminho_arquivo)):
            detalhes.append(f"aviso: nome do arquivo difere do registrado ({sig.nome_arquivo!r})")
        detalhes.append(f"digest SHA3-256: {digest_atual.hex()}")
        detalhes.append(f"chave do signatário: {fp}")
        return ResultadoVerificacao(Status.VALIDA, detalhes)

    # Diagnóstico (baseado em metadados não autenticados — apenas informativo).
    if digest_atual != sig.digest or os.path.getsize(caminho_arquivo) != sig.tamanho_arquivo:
        detalhes.append(f"digest registrado: {sig.digest.hex()}")
        detalhes.append(f"digest atual:      {digest_atual.hex()}")
        return ResultadoVerificacao(Status.ARQUIVO_ALTERADO, detalhes)
    if sig.impressao_digital != fp or sig.bits_chave != chave.bits:
        detalhes.append(f"impressão digital registrada: {sig.impressao_digital}")
        detalhes.append(f"impressão digital fornecida:  {fp}")
        return ResultadoVerificacao(Status.CHAVE_INCORRETA, detalhes)
    if len(sig.assinatura) != chave.k:
        detalhes.append(f"assinatura com {len(sig.assinatura)} bytes (esperado {chave.k})")
    else:
        detalhes.append("a verificação EMSA-PSS retornou 'inconsistente'")
    return ResultadoVerificacao(Status.ASSINATURA_INVALIDA, detalhes)
