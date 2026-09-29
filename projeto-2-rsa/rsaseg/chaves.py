"""Geração, validação e (de)serialização de chaves RSA.

Formato de arquivo (documentado em docs/formatos.md):

    -----BEGIN RSASEG PUBLIC KEY-----
    <Base64 de um JSON canônico, quebrado em linhas de 64 caracteres>
    -----END RSASEG PUBLIC KEY-----

O JSON contém os inteiros em hexadecimal minúsculo, sem prefixo.
"""

import base64
import binascii
import json
import os
import re
from dataclasses import dataclass

from .aritmetica import i2osp, inverso_modular, mmc, num_bytes
from .erros import ErroChave, ErroFormato, ErroParametro
from .hashing import sha3_256
from .primos import eh_provavel_primo, gerar_primo

BITS_MINIMO = 2048
E_PADRAO = 65537
VERSAO_FORMATO = "rsaseg-v1"
ROTULO_PUB = "RSASEG PUBLIC KEY"
ROTULO_PRIV = "RSASEG PRIVATE KEY"
_HEX = re.compile(r"^[0-9a-f]+$")


# --------------------------------------------------------------------------
# Estruturas
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ChavePublica:
    n: int
    e: int

    @property
    def bits(self) -> int:
        return self.n.bit_length()

    @property
    def k(self) -> int:
        """Tamanho do módulo em octetos."""
        return num_bytes(self.n)

    def validar(self) -> None:
        if self.bits < BITS_MINIMO:
            raise ErroChave(f"módulo com {self.bits} bits (< {BITS_MINIMO})")
        if self.n % 2 == 0:
            raise ErroChave("módulo par")
        if not (65537 <= self.e < (1 << 256)) or self.e % 2 == 0:
            raise ErroChave("expoente público fora da política (FIPS 186-5: 2^16 < e < 2^256, ímpar)")
        if self.e >= self.n:
            raise ErroChave("e >= n")

    def impressao_digital(self) -> str:
        """SHA3-256( 'rsaseg-pub' || I2OSP(n,k) || I2OSP(e, len(e)) ) em hexadecimal."""
        dados = b"rsaseg-pub" + i2osp(self.n, self.k) + i2osp(self.e, num_bytes(self.e))
        return sha3_256(dados).hex()


@dataclass(frozen=True, repr=False)
class ChavePrivada:
    n: int
    e: int
    d: int
    p: int
    q: int
    dp: int    # d mod (p-1)
    dq: int    # d mod (q-1)
    qinv: int  # q^-1 mod p

    def __repr__(self) -> str:  # nunca imprimir segredos por acidente
        return f"ChavePrivada(bits={self.n.bit_length()}, e={self.e}, <segredos omitidos>)"

    @property
    def bits(self) -> int:
        return self.n.bit_length()

    @property
    def k(self) -> int:
        return num_bytes(self.n)

    def publica(self) -> ChavePublica:
        return ChavePublica(self.n, self.e)

    def validar(self, rodadas_mr: int = 10) -> None:
        """Verifica a consistência de todos os parâmetros (útil na importação)."""
        self.publica().validar()
        if self.p * self.q != self.n:
            raise ErroChave("n != p*q")
        if self.p == self.q:
            raise ErroChave("p == q")
        if not (eh_provavel_primo(self.p, rodadas_mr) and eh_provavel_primo(self.q, rodadas_mr)):
            raise ErroChave("p ou q não é primo")
        lam = mmc(self.p - 1, self.q - 1)
        if not (1 < self.d < self.n) or (self.e * self.d) % lam != 1:
            raise ErroChave("e*d != 1 mod lambda(n)")
        if self.dp != self.d % (self.p - 1) or self.dq != self.d % (self.q - 1):
            raise ErroChave("expoentes CRT inconsistentes")
        if (self.qinv * self.q) % self.p != 1:
            raise ErroChave("qInv inconsistente")


# --------------------------------------------------------------------------
# Geração
# --------------------------------------------------------------------------

def gerar_par_chaves(bits: int = BITS_MINIMO, e: int = E_PADRAO) -> ChavePrivada:
    """Gera um par de chaves RSA (NIST SP 800-56B / FIPS 186-5).

    - p, q primos de bits/2 bits via Miller-Rabin, com mdc(p-1, e) = 1;
    - |p - q| > 2^(bits/2 - 100);
    - d = e^-1 mod lambda(n), lambda(n) = mmc(p-1, q-1), e d > 2^(bits/2);
    - parâmetros CRT dP, dQ, qInv para decifragem/assinatura rápidas.
    """
    if bits < BITS_MINIMO:
        raise ErroParametro(f"o módulo deve ter pelo menos {BITS_MINIMO} bits")
    if bits % 2:
        raise ErroParametro("tamanho do módulo deve ser par")
    if not (65537 <= e < (1 << 256)) or e % 2 == 0:
        raise ErroParametro("e deve ser ímpar e 2^16 < e < 2^256")

    metade = bits // 2
    while True:
        p = gerar_primo(metade, e)
        q = gerar_primo(metade, e)
        if abs(p - q) <= (1 << (metade - 100)):
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        lam = mmc(p - 1, q - 1)
        d = inverso_modular(e, lam)
        if d <= (1 << metade):
            continue
        if p < q:  # convenção: p > q
            p, q = q, p
        return ChavePrivada(
            n=n, e=e, d=d, p=p, q=q,
            dp=d % (p - 1), dq=d % (q - 1), qinv=inverso_modular(q, p),
        )


# --------------------------------------------------------------------------
# Serialização
# --------------------------------------------------------------------------

def _envelope(rotulo: str, dados: dict) -> str:
    js = json.dumps(dados, sort_keys=True, separators=(",", ":")).encode("utf-8")
    b64 = base64.b64encode(js).decode("ascii")
    linhas = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {rotulo}-----\n" + "\n".join(linhas) + f"\n-----END {rotulo}-----\n"


def _desenvelope(texto: str, rotulo: str) -> dict:
    if not isinstance(texto, str):
        raise ErroFormato("conteúdo da chave deve ser texto")
    linhas = [l.strip() for l in texto.strip().splitlines() if l.strip()]
    if len(linhas) < 3 or linhas[0] != f"-----BEGIN {rotulo}-----" or linhas[-1] != f"-----END {rotulo}-----":
        raise ErroFormato(f"cabeçalho/rodapé '{rotulo}' ausente ou incorreto")
    try:
        bruto = base64.b64decode("".join(linhas[1:-1]), validate=True)
        dados = json.loads(bruto.decode("utf-8"))
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise ErroFormato("conteúdo Base64/JSON inválido") from exc
    if not isinstance(dados, dict):
        raise ErroFormato("estrutura JSON inválida")
    return dados


def _hex(x: int) -> str:
    return format(x, "x")


def _ler_hex(dados: dict, campo: str) -> int:
    v = dados.get(campo)
    if not isinstance(v, str) or not _HEX.match(v):
        raise ErroFormato(f"campo '{campo}' ausente ou não é hexadecimal")
    return int(v, 16)


def _checar_campos(dados: dict, tipo: str, esperados: set) -> None:
    if dados.get("formato") != VERSAO_FORMATO or dados.get("tipo") != tipo:
        raise ErroFormato("versão de formato ou tipo de chave não suportado")
    if set(dados) != esperados:
        raise ErroFormato("campos inesperados ou ausentes na chave")


def exportar_publica(chave: ChavePublica) -> str:
    return _envelope(ROTULO_PUB, {
        "formato": VERSAO_FORMATO, "tipo": "publica", "bits": chave.bits,
        "n": _hex(chave.n), "e": _hex(chave.e),
    })


def importar_publica(texto: str) -> ChavePublica:
    dados = _desenvelope(texto, ROTULO_PUB)
    _checar_campos(dados, "publica", {"formato", "tipo", "bits", "n", "e"})
    chave = ChavePublica(_ler_hex(dados, "n"), _ler_hex(dados, "e"))
    if dados["bits"] != chave.bits:
        raise ErroFormato("campo 'bits' não confere com o módulo")
    chave.validar()
    return chave


_CAMPOS_PRIV = ("n", "e", "d", "p", "q", "dp", "dq", "qinv")


def exportar_privada(chave: ChavePrivada) -> str:
    dados = {"formato": VERSAO_FORMATO, "tipo": "privada", "bits": chave.bits}
    dados.update({c: _hex(getattr(chave, c)) for c in _CAMPOS_PRIV})
    return _envelope(ROTULO_PRIV, dados)


def importar_privada(texto: str) -> ChavePrivada:
    dados = _desenvelope(texto, ROTULO_PRIV)
    _checar_campos(dados, "privada", {"formato", "tipo", "bits", *_CAMPOS_PRIV})
    chave = ChavePrivada(**{c: _ler_hex(dados, c) for c in _CAMPOS_PRIV})
    if dados["bits"] != chave.bits:
        raise ErroFormato("campo 'bits' não confere com o módulo")
    chave.validar()
    return chave


def salvar_texto(caminho, texto: str, privado: bool = False) -> None:
    """Grava o arquivo; chaves privadas são criadas com permissão 0600."""
    modo = 0o600 if privado else 0o644
    fd = os.open(caminho, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, modo)
    with os.fdopen(fd, "w", encoding="ascii") as f:
        f.write(texto)


def ler_texto(caminho) -> str:
    with open(caminho, "r", encoding="ascii", errors="strict") as f:
        return f.read()
