"""RSAES-OAEP com SHA3-256 e MGF1-SHA3-256 (RFC 8017, seção 7.1).

Estrutura do bloco codificado (k = tamanho do módulo em bytes, hLen = 32):

    DB  = lHash || PS (zeros) || 0x01 || M                 (k - hLen - 1 bytes)
    maskedDB   = DB   XOR MGF1(seed,     k - hLen - 1)
    maskedSeed = seed XOR MGF1(maskedDB, hLen)
    EM  = 0x00 || maskedSeed || maskedDB                   (k bytes)

Tamanho máximo da mensagem: k - 2*hLen - 2 (190 bytes para RSA-2048).
"""

import hmac
import secrets

from .aritmetica import i2osp, os2ip, xor_bytes
from .chaves import ChavePrivada, ChavePublica
from .erros import ErroDecifragem, ErroParametro, ErroRSA, MensagemMuitoLonga
from .hashing import H_LEN, mgf1, sha3_256
from .primitivas import rsadp, rsaep


def tamanho_maximo_mensagem(chave: ChavePublica) -> int:
    return chave.k - 2 * H_LEN - 2


def _bytes(x, nome: str) -> bytes:
    if not isinstance(x, (bytes, bytearray)):
        raise ErroParametro(f"{nome} deve ser bytes")
    return bytes(x)


def codificar_oaep(mensagem: bytes, k: int, rotulo: bytes = b"", semente: bytes = None) -> bytes:
    """EME-OAEP encoding. ``semente`` só deve ser passada em testes."""
    m_len = len(mensagem)
    if m_len > k - 2 * H_LEN - 2:
        raise MensagemMuitoLonga(f"mensagem de {m_len} bytes excede o máximo de {k - 2 * H_LEN - 2}")
    l_hash = sha3_256(rotulo)
    ps = b"\x00" * (k - m_len - 2 * H_LEN - 2)
    db = l_hash + ps + b"\x01" + mensagem
    if semente is None:
        semente = secrets.token_bytes(H_LEN)
    elif len(semente) != H_LEN:
        raise ErroParametro("semente com tamanho incorreto")
    masked_db = xor_bytes(db, mgf1(semente, k - H_LEN - 1))
    masked_seed = xor_bytes(semente, mgf1(masked_db, H_LEN))
    return b"\x00" + masked_seed + masked_db


def decodificar_oaep(em: bytes, k: int, rotulo: bytes = b"") -> bytes:
    """EME-OAEP decoding.

    Todas as verificações são feitas antes de decidir, e qualquer falha
    produz a MESMA exceção genérica (sem indicar qual verificação falhou),
    para não criar um oráculo de padding. Python não oferece garantia de
    tempo constante, mas evitamos desvios dependentes dos dados secretos.
    """
    l_hash = sha3_256(rotulo)
    y = em[0]
    masked_seed = em[1 : 1 + H_LEN]
    masked_db = em[1 + H_LEN :]
    semente = xor_bytes(masked_seed, mgf1(masked_db, H_LEN))
    db = xor_bytes(masked_db, mgf1(semente, k - H_LEN - 1))

    ruim = int(y != 0)
    ruim |= int(not hmac.compare_digest(db[:H_LEN], l_hash))

    # Localiza o separador 0x01 após PS sem sair do laço mais cedo.
    procurando, indice = 1, 0
    for i in range(H_LEN, len(db)):
        b = db[i]
        eh_um, eh_zero = int(b == 1), int(b == 0)
        sel = procurando & eh_um
        indice = indice * (1 - sel) + i * sel
        ruim |= procurando & (1 - eh_zero) & (1 - eh_um)  # byte != 0 antes do 0x01
        procurando &= 1 - eh_um
    ruim |= procurando  # nenhum 0x01 encontrado

    if ruim:
        raise ErroDecifragem()
    return db[indice + 1 :]


def cifrar(chave: ChavePublica, mensagem: bytes, rotulo: bytes = b"") -> bytes:
    """RSAES-OAEP-ENCRYPT. Retorna o texto cifrado com exatamente k bytes."""
    mensagem = _bytes(mensagem, "mensagem")
    rotulo = _bytes(rotulo, "rótulo")
    k = chave.k
    if k < 2 * H_LEN + 2:
        raise ErroParametro("módulo pequeno demais para OAEP com SHA3-256")
    em = codificar_oaep(mensagem, k, rotulo)
    c = rsaep(chave, os2ip(em))
    return i2osp(c, k)


def decifrar(chave: ChavePrivada, texto_cifrado: bytes, rotulo: bytes = b"") -> bytes:
    """RSAES-OAEP-DECRYPT. Qualquer falha -> ErroDecifragem ('decryption error')."""
    try:
        texto_cifrado = _bytes(texto_cifrado, "texto cifrado")
        rotulo = _bytes(rotulo, "rótulo")
    except ErroParametro:
        raise ErroDecifragem() from None
    k = chave.k
    if len(texto_cifrado) != k or k < 2 * H_LEN + 2:
        raise ErroDecifragem()
    c = os2ip(texto_cifrado)
    try:
        m = rsadp(chave, c)
        em = i2osp(m, k)
    except ErroRSA:
        raise ErroDecifragem() from None
    return decodificar_oaep(em, k, rotulo)
