"""Primitivas RSA "cruas" (RFC 8017, seção 5).

ATENÇÃO: estas funções são o RSA "de livro-texto" e NUNCA devem ser usadas
diretamente sobre mensagens — elas só são chamadas pelos esquemas
RSAES-OAEP (cifragem) e RSASSA-PSS (assinatura). Ver docs/analise_seguranca.md.

Cifragem e assinatura usam a MESMA operação matemática, mas com papéis e
chaves distintos:
  * RSAEP  (cifrar)     : c = m^e mod n      -> chave PÚBLICA do destinatário
  * RSADP  (decifrar)   : m = c^d mod n      -> chave PRIVADA do destinatário
  * RSASP1 (assinar)    : s = m^d mod n      -> chave PRIVADA do signatário
  * RSAVP1 (verificar)  : m = s^e mod n      -> chave PÚBLICA do signatário
"""

import secrets

from .aritmetica import exp_modular, inverso_modular, mdc
from .chaves import ChavePrivada, ChavePublica
from .erros import ErroParametro, ErroRSA


def _operacao_privada(chave: ChavePrivada, x: int) -> int:
    """x^d mod n usando CRT, com blinding e verificação contra falhas.

    * Blinding: x' = x * r^e mod n com r aleatório; calcula-se x'^d = x^d * r
      e multiplica-se por r^-1. O tempo de execução deixa de depender de x,
      mitigando ataques de temporização (Kocher).
    * Verificação: confere (resultado^e mod n) == x' para evitar vazamento
      de p/q por falhas de cálculo no CRT (ataque de Boneh-DeMillo-Lipton).
    """
    n = chave.n
    while True:
        r = secrets.randbelow(n - 2) + 2
        if mdc(r, n) == 1:
            break
    x_cego = (x * exp_modular(r, chave.e, n)) % n

    m1 = exp_modular(x_cego, chave.dp, chave.p)
    m2 = exp_modular(x_cego, chave.dq, chave.q)
    h = (chave.qinv * (m1 - m2)) % chave.p
    y_cego = m2 + h * chave.q

    if exp_modular(y_cego, chave.e, n) != x_cego:
        raise ErroRSA("falha interna na operação privada (verificação CRT)")
    return (y_cego * inverso_modular(r, n)) % n


def rsaep(chave: ChavePublica, m: int) -> int:
    if not (0 <= m < chave.n):
        raise ErroParametro("representante da mensagem fora do intervalo")
    return exp_modular(m, chave.e, chave.n)


def rsadp(chave: ChavePrivada, c: int) -> int:
    if not (0 <= c < chave.n):
        raise ErroParametro("representante do texto cifrado fora do intervalo")
    return _operacao_privada(chave, c)


def rsasp1(chave: ChavePrivada, m: int) -> int:
    if not (0 <= m < chave.n):
        raise ErroParametro("representante da mensagem fora do intervalo")
    return _operacao_privada(chave, m)


def rsavp1(chave: ChavePublica, s: int) -> int:
    if not (0 <= s < chave.n):
        raise ErroParametro("representante da assinatura fora do intervalo")
    return exp_modular(s, chave.e, chave.n)
