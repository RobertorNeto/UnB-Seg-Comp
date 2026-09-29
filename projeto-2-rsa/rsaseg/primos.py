"""Teste de primalidade Miller-Rabin e geração de primos grandes.

Referências: NIST FIPS 186-5, Apêndices A.1.3 e B.3; NIST SP 800-56B Rev. 2.
A aleatoriedade vem de ``secrets`` (CSPRNG do sistema operacional).
"""

import secrets

from .aritmetica import exp_modular, mdc
from .erros import ErroParametro

# Número padrão de rodadas. Para um composto arbitrário a probabilidade de
# erro por rodada é <= 1/4, logo 40 rodadas dão <= 2^-80 no pior caso; para
# candidatos aleatórios de 1024 bits a probabilidade real é muito menor
# (FIPS 186-5, Tabela B.1, exige apenas 5 rodadas para 2^-100 nesse caso).
RODADAS_PADRAO = 40


def _crivo(limite: int):
    marcado = bytearray([1]) * (limite + 1)
    marcado[0:2] = b"\x00\x00"
    for i in range(2, int(limite ** 0.5) + 1):
        if marcado[i]:
            marcado[i * i :: i] = bytearray(len(marcado[i * i :: i]))
    return [i for i, v in enumerate(marcado) if v]


PRIMOS_PEQUENOS = _crivo(2000)


def nucleo_miller_rabin(n: int, rodadas: int = RODADAS_PADRAO) -> bool:
    """Miller-Rabin puro (sem divisão por tentativa).

    Escreve n - 1 = 2^s * d com d ímpar e, para ``rodadas`` bases aleatórias
    a em [2, n-2], verifica se a é testemunha de composição.
    Retorna False => n certamente composto; True => provavelmente primo.
    """
    if not isinstance(n, int) or isinstance(n, bool):
        raise ErroParametro("n deve ser inteiro")
    if rodadas < 1:
        raise ErroParametro("rodadas deve ser >= 1")
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1

    for _ in range(rodadas):
        a = secrets.randbelow(n - 3) + 2  # a em [2, n-2]
        x = exp_modular(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False  # a é testemunha: n é composto
    return True


def eh_provavel_primo(n: int, rodadas: int = RODADAS_PADRAO) -> bool:
    """Divisão por primos pequenos (filtro barato) seguida de Miller-Rabin."""
    if not isinstance(n, int) or isinstance(n, bool):
        raise ErroParametro("n deve ser inteiro")
    if n < 2:
        return False
    for p in PRIMOS_PEQUENOS:
        if n == p:
            return True
        if n % p == 0:
            return False
    return nucleo_miller_rabin(n, rodadas)


def gerar_primo(bits: int, e: int = None, rodadas: int = RODADAS_PADRAO) -> int:
    """Gera um primo provável com exatamente ``bits`` bits.

    Os dois bits mais significativos são fixados em 1, o que garante
    p >= 1.5 * 2^(bits-1) > sqrt(2) * 2^(bits-1) (condição do FIPS 186-5) e
    que o produto de dois primos desse tamanho tenha exatamente 2*bits bits.
    Se ``e`` for dado, exige-se mdc(p - 1, e) = 1.
    """
    if bits < 16:
        raise ErroParametro("tamanho de primo muito pequeno")
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if e is not None and mdc(c - 1, e) != 1:
            continue
        if eh_provavel_primo(c, rodadas):
            return c
