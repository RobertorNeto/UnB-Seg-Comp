"""RSASSA-PSS com SHA3-256 e MGF1-SHA3-256 (RFC 8017, seções 8.1 e 9.1).

Isto NÃO é "cifrar o hash com a chave privada". O digest mHash passa por
uma codificação probabilística (EMSA-PSS) antes da operação privada:

    M'       = 0x00*8 || mHash || salt
    H        = Hash(M')
    DB       = PS (zeros) || 0x01 || salt
    maskedDB = DB XOR MGF1(H, emLen - hLen - 1)   (bits mais à esquerda zerados)
    EM       = maskedDB || H || 0xBC
    s        = RSASP1(K_priv, OS2IP(EM))

emBits = modBits - 1 garante OS2IP(EM) < n.
"""

import hmac
import secrets

from .aritmetica import i2osp, os2ip, xor_bytes
from .chaves import ChavePrivada, ChavePublica
from .erros import ErroParametro, ErroRSA
from .hashing import H_LEN, mgf1, sha3_256
# PSS usa as primitivas de ASSINATURA (RSASP1/RSAVP1), não as de cifragem.
from .primitivas import rsasp1 as _rsasp1, rsavp1 as _rsavp1

SALT_LEN_PADRAO = H_LEN  # 32 bytes, recomendação usual (sLen = hLen)


def _mascara_bits_esquerda(em_len: int, em_bits: int) -> int:
    """Máscara para o 1º byte, zerando os 8*emLen - emBits bits mais altos."""
    return 0xFF >> (8 * em_len - em_bits)


def codificar_pss(m_hash: bytes, em_bits: int, salt_len: int = SALT_LEN_PADRAO, salt: bytes = None) -> bytes:
    """EMSA-PSS-ENCODE. ``salt`` explícito só deve ser usado em testes."""
    if len(m_hash) != H_LEN:
        raise ErroParametro("mHash com tamanho incorreto")
    if salt_len < 0:
        raise ErroParametro("salt_len negativo")
    em_len = -(-em_bits // 8)
    if em_len < H_LEN + salt_len + 2:
        raise ErroParametro("encoding error: módulo pequeno para hLen + sLen")
    if salt is None:
        salt = secrets.token_bytes(salt_len)
    elif len(salt) != salt_len:
        raise ErroParametro("salt com tamanho incorreto")

    m_linha = b"\x00" * 8 + m_hash + salt
    h = sha3_256(m_linha)
    ps = b"\x00" * (em_len - salt_len - H_LEN - 2)
    db = ps + b"\x01" + salt
    masked_db = bytearray(xor_bytes(db, mgf1(h, em_len - H_LEN - 1)))
    masked_db[0] &= _mascara_bits_esquerda(em_len, em_bits)
    return bytes(masked_db) + h + b"\xbc"


def verificar_codificacao_pss(m_hash: bytes, em: bytes, em_bits: int, salt_len: int = SALT_LEN_PADRAO) -> bool:
    """EMSA-PSS-VERIFY: True = 'consistent', False = 'inconsistent'."""
    if len(m_hash) != H_LEN or salt_len < 0:
        return False
    em_len = -(-em_bits // 8)
    if len(em) != em_len or em_len < H_LEN + salt_len + 2:
        return False
    if em[-1] != 0xBC:
        return False
    masked_db = em[: em_len - H_LEN - 1]
    h = em[em_len - H_LEN - 1 : -1]
    mascara = _mascara_bits_esquerda(em_len, em_bits)
    if masked_db[0] & (~mascara & 0xFF):
        return False
    db = bytearray(xor_bytes(masked_db, mgf1(h, em_len - H_LEN - 1)))
    db[0] &= mascara
    n_zeros = em_len - H_LEN - salt_len - 2
    if any(db[:n_zeros]) or db[n_zeros] != 0x01:
        return False
    salt = bytes(db[len(db) - salt_len :]) if salt_len else b""
    h_linha = sha3_256(b"\x00" * 8 + m_hash + salt)
    return hmac.compare_digest(h, h_linha)


def assinar_digest(chave: ChavePrivada, m_hash: bytes, salt_len: int = SALT_LEN_PADRAO) -> bytes:
    """RSASSA-PSS-SIGN a partir do digest SHA3-256 já calculado."""
    mod_bits = chave.bits
    em = codificar_pss(m_hash, mod_bits - 1, salt_len)
    s = _rsasp1(chave, os2ip(em))
    return i2osp(s, chave.k)


def verificar_digest(chave: ChavePublica, m_hash: bytes, assinatura: bytes, salt_len: int = SALT_LEN_PADRAO) -> bool:
    """RSASSA-PSS-VERIFY. Nunca lança exceção por dado adulterado: retorna False."""
    if not isinstance(assinatura, (bytes, bytearray)) or len(assinatura) != chave.k:
        return False
    s = os2ip(assinatura)
    try:
        m = _rsavp1(chave, s)
        em_bits = chave.bits - 1
        em = i2osp(m, -(-em_bits // 8))
    except ErroRSA:
        return False
    return verificar_codificacao_pss(m_hash, em, em_bits, salt_len)


def assinar(chave: ChavePrivada, mensagem: bytes, salt_len: int = SALT_LEN_PADRAO) -> bytes:
    return assinar_digest(chave, sha3_256(mensagem), salt_len)


def verificar(chave: ChavePublica, mensagem: bytes, assinatura: bytes, salt_len: int = SALT_LEN_PADRAO) -> bool:
    return verificar_digest(chave, sha3_256(mensagem), assinatura, salt_len)
