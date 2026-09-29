"""Aritmética modular e conversões de dados (RFC 8017, seção 4).

Implementações próprias — não usamos ``pow(a, b, m)`` nem ``pow(a, -1, m)``
do Python para as operações criptográficas, justamente para que a aritmética
modular faça parte do trabalho avaliado.
"""

from .erros import ErroParametro


def mdc(a: int, b: int) -> int:
    """Máximo divisor comum (algoritmo de Euclides)."""
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def mmc(a: int, b: int) -> int:
    """Mínimo múltiplo comum."""
    if a == 0 or b == 0:
        return 0
    return abs(a) // mdc(a, b) * abs(b)


def euclides_estendido(a: int, b: int):
    """Retorna (g, x, y) tais que a*x + b*y = g = mdc(a, b). Versão iterativa."""
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def inverso_modular(a: int, m: int) -> int:
    """Inverso multiplicativo de ``a`` módulo ``m``."""
    if m <= 1:
        raise ErroParametro("módulo deve ser > 1")
    g, x, _ = euclides_estendido(a % m, m)
    if g != 1:
        raise ErroParametro("elemento não é invertível no módulo dado")
    return x % m


def exp_modular(base: int, expoente: int, modulo: int) -> int:
    """Exponenciação modular por quadrados sucessivos (square-and-multiply).

    Processa o expoente da direita para a esquerda. Em Python não é possível
    garantir tempo constante; o risco de canal lateral de tempo nas operações
    privadas é mitigado com *blinding* (ver ``primitivas.py``).
    """
    if modulo <= 0:
        raise ErroParametro("módulo deve ser positivo")
    if expoente < 0:
        raise ErroParametro("expoente negativo não suportado")
    if modulo == 1:
        return 0
    resultado = 1
    base %= modulo
    while expoente:
        if expoente & 1:
            resultado = (resultado * base) % modulo
        base = (base * base) % modulo
        expoente >>= 1
    return resultado


def num_bytes(n: int) -> int:
    """Quantidade de octetos necessária para representar ``n``."""
    return (n.bit_length() + 7) // 8


def i2osp(x: int, tamanho: int) -> bytes:
    """Integer-to-Octet-String primitive (RFC 8017, 4.1)."""
    if x < 0 or x >= 256 ** tamanho:
        raise ErroParametro("inteiro grande demais")
    return x.to_bytes(tamanho, "big")


def os2ip(octetos: bytes) -> int:
    """Octet-String-to-Integer primitive (RFC 8017, 4.2)."""
    return int.from_bytes(octetos, "big")


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR byte a byte de duas sequências de mesmo tamanho."""
    if len(a) != len(b):
        raise ErroParametro("xor de sequências de tamanhos diferentes")
    if not a:
        return b""
    return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).to_bytes(len(a), "big")
