"""Função hash (SHA3-256, FIPS 202) e MGF1 (RFC 8017, B.2.1).

SHA3-256 vem do ``hashlib`` (biblioteca pública permitida pelo enunciado,
restrição 1). A MGF1 é implementação própria.
"""

import hashlib

from .aritmetica import i2osp
from .erros import ErroParametro

H_LEN = 32  # tamanho da saída do SHA3-256 em bytes
NOME_HASH = "SHA3-256"
NOME_MGF = "MGF1-SHA3-256"


def sha3_256(dados: bytes) -> bytes:
    return hashlib.sha3_256(dados).digest()


def sha3_256_arquivo(caminho, tamanho_bloco: int = 1 << 16) -> bytes:
    """Digest SHA3-256 de um arquivo, lido em blocos (serve para arquivos grandes)."""
    h = hashlib.sha3_256()
    with open(caminho, "rb") as f:
        while True:
            bloco = f.read(tamanho_bloco)
            if not bloco:
                break
            h.update(bloco)
    return h.digest()


def mgf1(semente: bytes, comprimento: int, hash_fn=sha3_256, h_len: int = H_LEN) -> bytes:
    """Mask Generation Function 1.

    T = Hash(semente || C(0)) || Hash(semente || C(1)) || ...
    onde C(i) = I2OSP(i, 4); devolve os ``comprimento`` primeiros octetos de T.
    """
    if comprimento < 0:
        raise ErroParametro("comprimento negativo")
    if comprimento > (1 << 32) * h_len:
        raise ErroParametro("mask too long")
    blocos = -(-comprimento // h_len)  # teto
    t = b"".join(hash_fn(semente + i2osp(i, 4)) for i in range(blocos))
    return t[:comprimento]
