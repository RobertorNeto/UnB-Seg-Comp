"""Utilitários de teste: chaves 2048 bits geradas uma única vez por execução."""

from rsaseg.chaves import gerar_par_chaves

_cache = {}


def chave(nome: str = "alice"):
    if nome not in _cache:
        _cache[nome] = gerar_par_chaves(2048)
    return _cache[nome]


def inverter_byte(dados: bytes, posicao: int, mascara: int = 0x01) -> bytes:
    b = bytearray(dados)
    b[posicao] ^= mascara
    return bytes(b)
