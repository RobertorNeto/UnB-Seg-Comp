#!/usr/bin/env python3
"""
===============================================================================
 CIC0201 - Segurança Computacional - Projeto 2
 Sistema de Assinatura Digital e Verificação Segura de Arquivos
 RSA-2048 + RSA-OAEP (cifragem) + RSA-PSS (assinatura), com SHA3-256 e MGF1

 Daniel de Oliveira Morais              - 242042396
 Davi Bragança e Silva                  - 242001473
 Roberto Ribeiro Correa de Oliveira Neto - 242009936
===============================================================================

Organização do arquivo (segue as partes do enunciado):

    0. Erros
    1. Aritmética modular ............................ (base da Parte I)
    2. Miller-Rabin e geração de primos .............. Parte I
    3. Chaves RSA: geração, exportação, importação ... Parte I
    4. SHA3-256 e MGF1 ............................... Partes II e III
    5. Operações RSA básicas (com CRT e blinding)
    6. RSA-OAEP: cifrar e decifrar ................... Parte II
    7. RSA-PSS: assinar e verificar .................. Parte III
    8. Arquivo de assinatura (.sig) e verificação .... Parte IV
    9. Demonstração e testes de adulteração .......... Partes IV e V
   10. Linha de comando

Uso:
    python3 rsa_assinatura.py demo
    python3 rsa_assinatura.py gerar-chaves --saida alice
    python3 rsa_assinatura.py cifrar     --chave alice.pub  --mensagem "segredo" --saida msg.enc
    python3 rsa_assinatura.py decifrar   --chave alice.priv --entrada msg.enc
    python3 rsa_assinatura.py assinar    --chave alice.priv --arquivo contrato.txt
    python3 rsa_assinatura.py verificar  --chave alice.pub  --arquivo contrato.txt --assinatura contrato.txt.sig

Dependências: só a biblioteca padrão do Python 3.8+
(hashlib para o SHA3-256, secrets para números aleatórios seguros).
Nenhuma operação RSA, Miller-Rabin, OAEP, MGF1 ou PSS vem de biblioteca pronta.
"""

import argparse
import base64
import binascii
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import tempfile
import time
from dataclasses import dataclass


# =============================================================================
# 0. ERROS
# =============================================================================

class ErroRSA(Exception):
    """Erro base: toda falha previsível do sistema é uma subclasse deste."""


class ErroEntradaInvalida(ErroRSA, ValueError):
    """Parâmetro com tamanho, tipo ou intervalo inválido."""


class ErroMensagemMuitoLonga(ErroRSA):
    """A mensagem não cabe no OAEP (máximo de 190 bytes para RSA-2048)."""


class ErroDecifragem(ErroRSA):
    """Falha ao decifrar. A mensagem é SEMPRE a mesma, qualquer que seja a
    causa, para não dar pistas a um atacante (ataque de Manger)."""

    def __init__(self):
        super().__init__("falha na decifragem")


class ErroFormato(ErroRSA):
    """Arquivo de chave ou de assinatura malformado."""


class ErroChave(ErroRSA):
    """Chave inconsistente ou fraca demais."""


# =============================================================================
# 1. ARITMÉTICA MODULAR
#    Implementação própria: não usamos pow(a, b, m) nem pow(a, -1, m).
# =============================================================================

def mdc(a, b):
    """Máximo divisor comum (algoritmo de Euclides)."""
    a, b = abs(a), abs(b)
    while b != 0:
        a, b = b, a % b
    return a


def mmc(a, b):
    """Mínimo múltiplo comum."""
    return abs(a) // mdc(a, b) * abs(b)


def euclides_estendido(a, b):
    """Retorna (g, x, y) tais que a*x + b*y = g = mdc(a, b)."""
    x_anterior, x_atual = 1, 0
    y_anterior, y_atual = 0, 1
    while b != 0:
        quociente = a // b
        a, b = b, a % b
        x_anterior, x_atual = x_atual, x_anterior - quociente * x_atual
        y_anterior, y_atual = y_atual, y_anterior - quociente * y_atual
    return a, x_anterior, y_anterior


def inverso_modular(a, modulo):
    """Retorna x tal que (a * x) % modulo == 1."""
    if modulo <= 1:
        raise ErroEntradaInvalida("o módulo deve ser maior que 1")
    g, x, _ = euclides_estendido(a % modulo, modulo)
    if g != 1:
        raise ErroEntradaInvalida("o número não tem inverso nesse módulo")
    return x % modulo


def potencia_modular(base, expoente, modulo):
    """Calcula (base ** expoente) % modulo por quadrados sucessivos.

    Percorre os bits do expoente: a cada bit a base é elevada ao quadrado,
    e quando o bit é 1 o resultado é multiplicado pela base atual.
    """
    if modulo <= 0 or expoente < 0:
        raise ErroEntradaInvalida("módulo deve ser positivo e expoente não negativo")
    if modulo == 1:
        return 0
    resultado = 1
    base = base % modulo
    while expoente > 0:
        if expoente & 1:
            resultado = (resultado * base) % modulo
        base = (base * base) % modulo
        expoente >>= 1
    return resultado


def tamanho_em_bytes(numero):
    """Quantos bytes são necessários para representar o número."""
    return (numero.bit_length() + 7) // 8


def inteiro_para_bytes(numero, tamanho):
    """I2OSP da RFC 8017: inteiro -> bytes big-endian com tamanho fixo."""
    if numero < 0 or numero >= 256 ** tamanho:
        raise ErroEntradaInvalida("inteiro grande demais para o tamanho pedido")
    return numero.to_bytes(tamanho, "big")


def bytes_para_inteiro(dados):
    """OS2IP da RFC 8017: bytes big-endian -> inteiro."""
    return int.from_bytes(dados, "big")


def xor_bytes(a, b):
    """XOR byte a byte de duas sequências do mesmo tamanho."""
    if len(a) != len(b):
        raise ErroEntradaInvalida("xor entre sequências de tamanhos diferentes")
    return bytes(x ^ y for x, y in zip(a, b))


# =============================================================================
# 2. MILLER-RABIN E GERAÇÃO DE PRIMOS  (Parte I)
# =============================================================================

RODADAS_MILLER_RABIN = 40   # erro <= (1/4)^40 = 2^-80 no pior caso


def listar_primos_ate(limite):
    """Crivo de Eratóstenes."""
    eh_primo = [True] * (limite + 1)
    eh_primo[0] = eh_primo[1] = False
    for i in range(2, int(limite ** 0.5) + 1):
        if eh_primo[i]:
            for multiplo in range(i * i, limite + 1, i):
                eh_primo[multiplo] = False
    return [i for i in range(limite + 1) if eh_primo[i]]


PRIMOS_PEQUENOS = listar_primos_ate(2000)


def teste_miller_rabin(n, rodadas=RODADAS_MILLER_RABIN):
    """Teste probabilístico de primalidade de Miller-Rabin.

    1. Escreve n - 1 = 2^s * d, com d ímpar.
    2. Sorteia uma base a entre 2 e n - 2 e calcula x = a^d mod n.
    3. Se x for 1 ou n - 1, esta rodada não prova nada: passa para a próxima.
    4. Senão, eleva x ao quadrado até s - 1 vezes. Se nunca chegar a n - 1,
       a base "a" prova que n é composto.

    Retorna False se n é certamente composto, True se é provavelmente primo.
    """
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
        a = secrets.randbelow(n - 3) + 2          # base aleatória em [2, n-2]
        x = potencia_modular(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False                          # "a" provou que n é composto
    return True


def eh_provavel_primo(n, rodadas=RODADAS_MILLER_RABIN):
    """Filtro barato (divisão por primos pequenos) seguido de Miller-Rabin."""
    if n < 2:
        return False
    for p in PRIMOS_PEQUENOS:
        if n == p:
            return True
        if n % p == 0:
            return False
    return teste_miller_rabin(n, rodadas)


def gerar_primo(bits, e=65537):
    """Sorteia números ímpares de 'bits' bits até achar um primo.

    Os dois bits mais altos são ligados: isso garante que p * q tenha
    exatamente 2 * bits bits. Também exige mdc(p - 1, e) = 1 para que
    o expoente e tenha inverso.
    """
    while True:
        candidato = secrets.randbits(bits)
        candidato |= (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if mdc(candidato - 1, e) != 1:
            continue
        if eh_provavel_primo(candidato):
            return candidato


# =============================================================================
# 3. CHAVES RSA: GERAÇÃO, EXPORTAÇÃO E IMPORTAÇÃO  (Parte I)
# =============================================================================

TAMANHO_MINIMO_BITS = 2048
EXPOENTE_PUBLICO = 65537


@dataclass(frozen=True)
class ChavePublica:
    n: int      # módulo
    e: int      # expoente público

    @property
    def bits(self):
        return self.n.bit_length()

    @property
    def tamanho_bytes(self):
        return tamanho_em_bytes(self.n)

    def impressao_digital(self):
        """SHA3-256 da chave: serve para identificar qual chave assinou."""
        dados = b"rsaseg-pub" + inteiro_para_bytes(self.n, self.tamanho_bytes) \
            + inteiro_para_bytes(self.e, tamanho_em_bytes(self.e))
        return hashlib.sha3_256(dados).hexdigest()

    def validar(self):
        if self.bits < TAMANHO_MINIMO_BITS:
            raise ErroChave(f"módulo de {self.bits} bits é menor que {TAMANHO_MINIMO_BITS}")
        if self.n % 2 == 0:
            raise ErroChave("o módulo não pode ser par")
        if not (65537 <= self.e < 2 ** 256) or self.e % 2 == 0:
            raise ErroChave("o expoente público deve ser ímpar e entre 2^16 e 2^256")


@dataclass(frozen=True, repr=False)
class ChavePrivada:
    n: int
    e: int
    d: int       # expoente privado
    p: int       # primos
    q: int
    dp: int      # d mod (p - 1)   -> usados no Teorema Chinês dos Restos
    dq: int      # d mod (q - 1)
    qinv: int    # q^-1 mod p

    def __repr__(self):
        return f"ChavePrivada({self.bits} bits, segredos ocultos)"

    @property
    def bits(self):
        return self.n.bit_length()

    @property
    def tamanho_bytes(self):
        return tamanho_em_bytes(self.n)

    def chave_publica(self):
        return ChavePublica(self.n, self.e)

    def validar(self):
        """Confere se todos os parâmetros são coerentes entre si."""
        self.chave_publica().validar()
        if self.p * self.q != self.n or self.p == self.q:
            raise ErroChave("n diferente de p * q")
        if not (eh_provavel_primo(self.p, 10) and eh_provavel_primo(self.q, 10)):
            raise ErroChave("p ou q não é primo")
        if (self.e * self.d) % mmc(self.p - 1, self.q - 1) != 1:
            raise ErroChave("e * d não é 1 módulo lambda(n)")
        if self.dp != self.d % (self.p - 1) or self.dq != self.d % (self.q - 1):
            raise ErroChave("parâmetros do CRT inconsistentes")
        if (self.qinv * self.q) % self.p != 1:
            raise ErroChave("qinv inconsistente")


def gerar_par_de_chaves(bits=TAMANHO_MINIMO_BITS, e=EXPOENTE_PUBLICO):
    """Gera um par de chaves RSA seguindo o FIPS 186-5.

    - p e q: primos de bits/2 bits, gerados com Miller-Rabin;
    - p e q distantes: |p - q| > 2^(bits/2 - 100);
    - d = e^-1 mod lambda(n), com lambda(n) = mmc(p - 1, q - 1);
    - d precisa ser grande: d > 2^(bits/2).
    """
    if bits < TAMANHO_MINIMO_BITS or bits % 2 != 0:
        raise ErroEntradaInvalida(f"o módulo deve ser par e ter pelo menos {TAMANHO_MINIMO_BITS} bits")
    metade = bits // 2
    while True:
        p = gerar_primo(metade, e)
        q = gerar_primo(metade, e)
        if abs(p - q) <= 2 ** (metade - 100):
            continue
        n = p * q
        if n.bit_length() != bits:
            continue
        d = inverso_modular(e, mmc(p - 1, q - 1))
        if d <= 2 ** metade:
            continue
        if p < q:
            p, q = q, p
        return ChavePrivada(n=n, e=e, d=d, p=p, q=q,
                            dp=d % (p - 1), dq=d % (q - 1),
                            qinv=inverso_modular(q, p))


# ---- Formato de arquivo das chaves ------------------------------------------
#
#   -----BEGIN RSASEG PUBLIC KEY-----
#   <JSON em Base64, linhas de 64 caracteres>
#   -----END RSASEG PUBLIC KEY-----
#
#   JSON: {"formato":"rsaseg-v1","tipo":"publica","bits":2048,"n":"<hex>","e":"<hex>"}
#   A chave privada também traz d, p, q, dp, dq, qinv.

VERSAO_FORMATO = "rsaseg-v1"
ROTULO_CHAVE_PUBLICA = "RSASEG PUBLIC KEY"
ROTULO_CHAVE_PRIVADA = "RSASEG PRIVATE KEY"
CAMPOS_CHAVE_PRIVADA = ("n", "e", "d", "p", "q", "dp", "dq", "qinv")
PADRAO_HEX = re.compile(r"^[0-9a-f]+$")


def empacotar_em_texto(rotulo, dados):
    """Dicionário -> JSON -> Base64 entre linhas BEGIN/END."""
    json_bytes = json.dumps(dados, sort_keys=True, separators=(",", ":")).encode()
    b64 = base64.b64encode(json_bytes).decode()
    linhas = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {rotulo}-----\n" + "\n".join(linhas) + f"\n-----END {rotulo}-----\n"


def desempacotar_texto(texto, rotulo):
    """Inverso de empacotar_em_texto, com validação estrita."""
    linhas = [l.strip() for l in texto.strip().splitlines() if l.strip()]
    if (len(linhas) < 3 or linhas[0] != f"-----BEGIN {rotulo}-----"
            or linhas[-1] != f"-----END {rotulo}-----"):
        raise ErroFormato(f"cabeçalho '{rotulo}' ausente ou incorreto")
    try:
        dados = json.loads(base64.b64decode("".join(linhas[1:-1]), validate=True))
    except (binascii.Error, ValueError):
        raise ErroFormato("conteúdo Base64/JSON inválido") from None
    if not isinstance(dados, dict):
        raise ErroFormato("estrutura JSON inválida")
    return dados


def ler_campo_hex(dados, campo):
    valor = dados.get(campo)
    if not isinstance(valor, str) or not PADRAO_HEX.match(valor):
        raise ErroFormato(f"campo '{campo}' ausente ou não é hexadecimal")
    return int(valor, 16)


def exportar_chave_publica(chave):
    return empacotar_em_texto(ROTULO_CHAVE_PUBLICA, {
        "formato": VERSAO_FORMATO, "tipo": "publica", "bits": chave.bits,
        "n": format(chave.n, "x"), "e": format(chave.e, "x"),
    })


def importar_chave_publica(texto):
    dados = desempacotar_texto(texto, ROTULO_CHAVE_PUBLICA)
    if (dados.get("formato"), dados.get("tipo")) != (VERSAO_FORMATO, "publica") \
            or set(dados) != {"formato", "tipo", "bits", "n", "e"}:
        raise ErroFormato("campos da chave pública incorretos")
    chave = ChavePublica(ler_campo_hex(dados, "n"), ler_campo_hex(dados, "e"))
    if dados["bits"] != chave.bits:
        raise ErroFormato("campo 'bits' não confere com o módulo")
    chave.validar()
    return chave


def exportar_chave_privada(chave):
    dados = {"formato": VERSAO_FORMATO, "tipo": "privada", "bits": chave.bits}
    for campo in CAMPOS_CHAVE_PRIVADA:
        dados[campo] = format(getattr(chave, campo), "x")
    return empacotar_em_texto(ROTULO_CHAVE_PRIVADA, dados)


def importar_chave_privada(texto):
    dados = desempacotar_texto(texto, ROTULO_CHAVE_PRIVADA)
    if (dados.get("formato"), dados.get("tipo")) != (VERSAO_FORMATO, "privada") \
            or set(dados) != {"formato", "tipo", "bits", *CAMPOS_CHAVE_PRIVADA}:
        raise ErroFormato("campos da chave privada incorretos")
    chave = ChavePrivada(**{c: ler_campo_hex(dados, c) for c in CAMPOS_CHAVE_PRIVADA})
    if dados["bits"] != chave.bits:
        raise ErroFormato("campo 'bits' não confere com o módulo")
    chave.validar()
    return chave


def salvar_arquivo_texto(caminho, texto, eh_segredo=False):
    """Salva o texto; arquivos secretos são criados com permissão 0600."""
    permissao = 0o600 if eh_segredo else 0o644
    descritor = os.open(caminho, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, permissao)
    with os.fdopen(descritor, "w", encoding="utf-8") as arquivo:
        arquivo.write(texto)


def ler_arquivo_texto(caminho):
    with open(caminho, "r", encoding="utf-8") as arquivo:
        return arquivo.read()


# =============================================================================
# 4. SHA3-256 E MGF1  (Partes II e III)
# =============================================================================

TAMANHO_HASH = 32   # SHA3-256 produz 32 bytes


def sha3_256(dados):
    return hashlib.sha3_256(dados).digest()


def sha3_256_de_arquivo(caminho):
    """Hash do arquivo lido em blocos de 64 KiB (funciona com arquivos grandes)."""
    calculadora = hashlib.sha3_256()
    with open(caminho, "rb") as arquivo:
        for bloco in iter(lambda: arquivo.read(65536), b""):
            calculadora.update(bloco)
    return calculadora.digest()


def mgf1(semente, tamanho):
    """Mask Generation Function 1 (RFC 8017, B.2.1).

    Concatena SHA3-256(semente || contador) para contador = 0, 1, 2, ...
    (contador com 4 bytes) até ter 'tamanho' bytes.
    """
    if tamanho > (2 ** 32) * TAMANHO_HASH:
        raise ErroEntradaInvalida("máscara grande demais")
    mascara = b""
    contador = 0
    while len(mascara) < tamanho:
        mascara += sha3_256(semente + inteiro_para_bytes(contador, 4))
        contador += 1
    return mascara[:tamanho]


# =============================================================================
# 5. OPERAÇÕES RSA BÁSICAS
#
#    São o RSA "de livro-texto". NUNCA são aplicadas diretamente à mensagem:
#    só as usamos dentro do OAEP e do PSS.
#
#      cifrar    : c = m^e mod n   -> chave PÚBLICA de quem vai receber
#      decifrar  : m = c^d mod n   -> chave PRIVADA de quem recebeu
#      assinar   : s = m^d mod n   -> chave PRIVADA de quem assina
#      verificar : m = s^e mod n   -> chave PÚBLICA de quem assinou
# =============================================================================

def rsa_operacao_publica(chave, x):
    """x^e mod n (usada para cifrar e para verificar assinatura)."""
    if not (0 <= x < chave.n):
        raise ErroEntradaInvalida("valor fora do intervalo [0, n)")
    return potencia_modular(x, chave.e, chave.n)


def rsa_operacao_privada(chave, x):
    """x^d mod n (usada para decifrar e para assinar), com três proteções:

    1. CRT (Teorema Chinês dos Restos): faz duas exponenciações de 1024 bits
       em vez de uma de 2048, cerca de 3x mais rápido.
    2. Blinding: multiplica x por r^e aleatório antes e divide por r depois.
       Assim o tempo gasto não depende de x (proteção contra ataques de tempo).
    3. Verificação: confere o resultado com a chave pública. Um erro de cálculo
       no CRT poderia revelar p e q (ataque de Boneh-DeMillo-Lipton).
    """
    if not (0 <= x < chave.n):
        raise ErroEntradaInvalida("valor fora do intervalo [0, n)")
    n = chave.n

    # 2. blinding
    while True:
        r = secrets.randbelow(n - 2) + 2
        if mdc(r, n) == 1:
            break
    x_mascarado = (x * potencia_modular(r, chave.e, n)) % n

    # 1. CRT
    m1 = potencia_modular(x_mascarado, chave.dp, chave.p)
    m2 = potencia_modular(x_mascarado, chave.dq, chave.q)
    h = (chave.qinv * (m1 - m2)) % chave.p
    y_mascarado = m2 + h * chave.q

    # 3. verificação
    if potencia_modular(y_mascarado, chave.e, n) != x_mascarado:
        raise ErroRSA("falha interna na operação privada")

    return (y_mascarado * inverso_modular(r, n)) % n


# =============================================================================
# 6. RSA-OAEP: CIFRAR E DECIFRAR  (Parte II)
#
#    Bloco montado antes da operação RSA (k = 256 bytes para RSA-2048):
#
#      DB          = hash(rótulo) || 00 00 ... 00 || 01 || mensagem
#      DB_mascarado      = DB      XOR MGF1(semente)
#      semente_mascarada = semente XOR MGF1(DB_mascarado)
#      bloco       = 00 || semente_mascarada || DB_mascarado
# =============================================================================

def tamanho_maximo_oaep(chave):
    """k - 2*hLen - 2 = 190 bytes para RSA-2048 com SHA3-256."""
    return chave.tamanho_bytes - 2 * TAMANHO_HASH - 2


def oaep_montar_bloco(mensagem, k, rotulo=b""):
    """Codificação EME-OAEP."""
    if len(mensagem) > k - 2 * TAMANHO_HASH - 2:
        raise ErroMensagemMuitoLonga(
            f"mensagem de {len(mensagem)} bytes; o máximo é {k - 2 * TAMANHO_HASH - 2}")
    hash_rotulo = sha3_256(rotulo)
    zeros = b"\x00" * (k - len(mensagem) - 2 * TAMANHO_HASH - 2)
    db = hash_rotulo + zeros + b"\x01" + mensagem

    semente = secrets.token_bytes(TAMANHO_HASH)          # torna a cifragem aleatória
    db_mascarado = xor_bytes(db, mgf1(semente, k - TAMANHO_HASH - 1))
    semente_mascarada = xor_bytes(semente, mgf1(db_mascarado, TAMANHO_HASH))
    return b"\x00" + semente_mascarada + db_mascarado


def oaep_abrir_bloco(bloco, k, rotulo=b""):
    """Decodificação EME-OAEP.

    Faz TODAS as verificações antes de decidir e, em qualquer falha, lança
    o mesmo erro genérico. Assim o atacante não descobre qual parte falhou.
    """
    semente_mascarada = bloco[1:1 + TAMANHO_HASH]
    db_mascarado = bloco[1 + TAMANHO_HASH:]
    semente = xor_bytes(semente_mascarada, mgf1(db_mascarado, TAMANHO_HASH))
    db = xor_bytes(db_mascarado, mgf1(semente, k - TAMANHO_HASH - 1))

    invalido = bloco[0] != 0
    invalido |= not hmac.compare_digest(db[:TAMANHO_HASH], sha3_256(rotulo))

    # Procura o separador 0x01 depois dos zeros, sem sair do laço mais cedo.
    posicao_separador = -1
    for i in range(TAMANHO_HASH, len(db)):
        if posicao_separador == -1:
            if db[i] == 0x01:
                posicao_separador = i
            elif db[i] != 0x00:
                invalido = True
    invalido |= posicao_separador == -1

    if invalido:
        raise ErroDecifragem()
    return db[posicao_separador + 1:]


def oaep_cifrar(chave_publica, mensagem, rotulo=b""):
    """RSAES-OAEP-ENCRYPT: devolve o texto cifrado (256 bytes para RSA-2048)."""
    k = chave_publica.tamanho_bytes
    bloco = oaep_montar_bloco(mensagem, k, rotulo)
    c = rsa_operacao_publica(chave_publica, bytes_para_inteiro(bloco))
    return inteiro_para_bytes(c, k)


def oaep_decifrar(chave_privada, texto_cifrado, rotulo=b""):
    """RSAES-OAEP-DECRYPT: qualquer problema vira ErroDecifragem."""
    k = chave_privada.tamanho_bytes
    if not isinstance(texto_cifrado, (bytes, bytearray)) or len(texto_cifrado) != k:
        raise ErroDecifragem()
    try:
        m = rsa_operacao_privada(chave_privada, bytes_para_inteiro(texto_cifrado))
        bloco = inteiro_para_bytes(m, k)
    except ErroRSA:
        raise ErroDecifragem() from None
    return oaep_abrir_bloco(bloco, k, rotulo)


# =============================================================================
# 7. RSA-PSS: ASSINAR E VERIFICAR  (Parte III)
#
#    Assinar NÃO é "cifrar o hash com a chave privada". O hash passa antes
#    por uma codificação aleatória (EMSA-PSS):
#
#      M'           = 00 x 8 || hash_arquivo || salt
#      H            = SHA3-256(M')
#      DB           = 00 00 ... 00 || 01 || salt
#      DB_mascarado = DB XOR MGF1(H)       (primeiro bit zerado)
#      bloco        = DB_mascarado || H || BC
#      assinatura   = bloco^d mod n
# =============================================================================

TAMANHO_SALT = 32


def pss_montar_bloco(hash_mensagem, bits_bloco):
    """Codificação EMSA-PSS. bits_bloco = bits do módulo - 1."""
    tamanho_bloco = (bits_bloco + 7) // 8
    if tamanho_bloco < TAMANHO_HASH + TAMANHO_SALT + 2:
        raise ErroEntradaInvalida("módulo pequeno demais para o PSS")

    salt = secrets.token_bytes(TAMANHO_SALT)             # torna a assinatura aleatória
    h = sha3_256(b"\x00" * 8 + hash_mensagem + salt)
    zeros = b"\x00" * (tamanho_bloco - TAMANHO_SALT - TAMANHO_HASH - 2)
    db = zeros + b"\x01" + salt
    db_mascarado = bytearray(xor_bytes(db, mgf1(h, tamanho_bloco - TAMANHO_HASH - 1)))
    db_mascarado[0] &= 0xFF >> (8 * tamanho_bloco - bits_bloco)   # zera bits excedentes
    return bytes(db_mascarado) + h + b"\xbc"


def pss_conferir_bloco(hash_mensagem, bloco, bits_bloco):
    """Verificação EMSA-PSS: True se o bloco é consistente com o hash."""
    tamanho_bloco = (bits_bloco + 7) // 8
    if len(bloco) != tamanho_bloco or bloco[-1] != 0xBC:
        return False

    db_mascarado = bloco[:tamanho_bloco - TAMANHO_HASH - 1]
    h = bloco[tamanho_bloco - TAMANHO_HASH - 1:-1]
    mascara_primeiro_byte = 0xFF >> (8 * tamanho_bloco - bits_bloco)
    if db_mascarado[0] & ~mascara_primeiro_byte & 0xFF:
        return False

    db = bytearray(xor_bytes(db_mascarado, mgf1(h, tamanho_bloco - TAMANHO_HASH - 1)))
    db[0] &= mascara_primeiro_byte
    qtd_zeros = tamanho_bloco - TAMANHO_HASH - TAMANHO_SALT - 2
    if any(db[:qtd_zeros]) or db[qtd_zeros] != 0x01:
        return False

    salt = bytes(db[-TAMANHO_SALT:])
    h_recalculado = sha3_256(b"\x00" * 8 + hash_mensagem + salt)
    return hmac.compare_digest(h, h_recalculado)


def pss_assinar(chave_privada, hash_mensagem):
    """RSASSA-PSS-SIGN a partir do SHA3-256 da mensagem."""
    if len(hash_mensagem) != TAMANHO_HASH:
        raise ErroEntradaInvalida("o hash deve ter 32 bytes")
    bloco = pss_montar_bloco(hash_mensagem, chave_privada.bits - 1)
    s = rsa_operacao_privada(chave_privada, bytes_para_inteiro(bloco))
    return inteiro_para_bytes(s, chave_privada.tamanho_bytes)


def pss_verificar(chave_publica, hash_mensagem, assinatura):
    """RSASSA-PSS-VERIFY: devolve True/False, nunca lança erro por adulteração."""
    if not isinstance(assinatura, (bytes, bytearray)) or len(assinatura) != chave_publica.tamanho_bytes:
        return False
    try:
        m = rsa_operacao_publica(chave_publica, bytes_para_inteiro(assinatura))
        bits_bloco = chave_publica.bits - 1
        bloco = inteiro_para_bytes(m, (bits_bloco + 7) // 8)
    except ErroRSA:
        return False
    return pss_conferir_bloco(hash_mensagem, bloco, bits_bloco)


# =============================================================================
# 8. ARQUIVO DE ASSINATURA (.sig) E VERIFICAÇÃO  (Partes III e IV)
#
#   -----BEGIN RSASEG SIGNATURE-----
#   Version: 1
#   Algorithm: RSASSA-PSS
#   Hash: SHA3-256
#   MGF: MGF1-SHA3-256
#   Salt-Length: 32
#   Key-Bits: 2048
#   Key-Fingerprint: <impressão digital da chave pública>
#   File-Name: contrato.txt
#   File-Size: 1234
#   File-Digest: <SHA3-256 do arquivo em hexadecimal>
#   Signature:
#   <assinatura em Base64>
#   -----END RSASEG SIGNATURE-----
#
#   IMPORTANTE: os campos do cabeçalho não são confiáveis. A validade depende
#   só da verificação PSS sobre o hash RECALCULADO do arquivo recebido.
# =============================================================================

ROTULO_ASSINATURA = "RSASEG SIGNATURE"
CAMPOS_CABECALHO = ("Version", "Algorithm", "Hash", "MGF", "Salt-Length", "Key-Bits",
                    "Key-Fingerprint", "File-Name", "File-Size", "File-Digest")
VALORES_FIXOS = {"Version": "1", "Algorithm": "RSASSA-PSS",
                 "Hash": "SHA3-256", "MGF": "MGF1-SHA3-256", "Salt-Length": "32"}


@dataclass
class DadosAssinatura:
    bits_chave: int
    impressao_digital: str
    nome_arquivo: str
    tamanho_arquivo: int
    hash_arquivo: bytes
    assinatura: bytes


def assinar_arquivo(chave_privada, caminho):
    """Calcula o SHA3-256 do arquivo e assina com RSA-PSS."""
    nome = os.path.basename(caminho)
    if not nome or any(ord(c) < 32 for c in nome):
        raise ErroEntradaInvalida("nome de arquivo inválido")
    hash_arquivo = sha3_256_de_arquivo(caminho)
    return DadosAssinatura(
        bits_chave=chave_privada.bits,
        impressao_digital=chave_privada.chave_publica().impressao_digital(),
        nome_arquivo=nome,
        tamanho_arquivo=os.path.getsize(caminho),
        hash_arquivo=hash_arquivo,
        assinatura=pss_assinar(chave_privada, hash_arquivo),
    )


def gerar_texto_assinatura(dados):
    """DadosAssinatura -> texto do arquivo .sig."""
    b64 = base64.b64encode(dados.assinatura).decode()
    linhas = [f"-----BEGIN {ROTULO_ASSINATURA}-----"]
    linhas += [f"{campo}: {valor}" for campo, valor in VALORES_FIXOS.items()]
    linhas += [
        f"Key-Bits: {dados.bits_chave}",
        f"Key-Fingerprint: {dados.impressao_digital}",
        f"File-Name: {dados.nome_arquivo}",
        f"File-Size: {dados.tamanho_arquivo}",
        f"File-Digest: {dados.hash_arquivo.hex()}",
        "Signature:",
    ]
    linhas += [b64[i:i + 64] for i in range(0, len(b64), 64)]
    linhas.append(f"-----END {ROTULO_ASSINATURA}-----")
    return "\n".join(linhas) + "\n"


def ler_texto_assinatura(texto):
    """Parsing estrito do arquivo .sig. Qualquer desvio -> ErroFormato."""
    linhas = [l.rstrip("\r") for l in texto.strip().split("\n")]
    if (len(linhas) < 4 or linhas[0] != f"-----BEGIN {ROTULO_ASSINATURA}-----"
            or linhas[-1] != f"-----END {ROTULO_ASSINATURA}-----"):
        raise ErroFormato("delimitadores BEGIN/END ausentes ou incorretos")

    cabecalho = {}
    i = 1
    while i < len(linhas) - 1 and linhas[i] != "Signature:":
        if ": " not in linhas[i]:
            raise ErroFormato(f"linha malformada: {linhas[i][:40]!r}")
        campo, valor = linhas[i].split(": ", 1)
        if campo not in CAMPOS_CABECALHO or campo in cabecalho:
            raise ErroFormato(f"campo desconhecido ou repetido: {campo[:40]!r}")
        cabecalho[campo] = valor
        i += 1
    if i >= len(linhas) - 1:
        raise ErroFormato("seção 'Signature:' ausente")
    if set(cabecalho) != set(CAMPOS_CABECALHO):
        raise ErroFormato("campos ausentes no cabeçalho")

    # Só aceitamos exatamente os parâmetros implementados (sem negociar).
    for campo, esperado in VALORES_FIXOS.items():
        if cabecalho[campo] != esperado:
            raise ErroFormato(f"valor não suportado em {campo}: {cabecalho[campo][:40]!r}")
    if not (cabecalho["Key-Bits"].isdigit() and cabecalho["File-Size"].isdigit()):
        raise ErroFormato("Key-Bits e File-Size devem ser números")
    for campo in ("File-Digest", "Key-Fingerprint"):
        if not re.fullmatch(r"[0-9a-f]{64}", cabecalho[campo]):
            raise ErroFormato(f"{campo} deve ter 64 dígitos hexadecimais")

    try:
        assinatura = base64.b64decode("".join(linhas[i + 1:-1]), validate=True)
    except (binascii.Error, ValueError):
        raise ErroFormato("assinatura não é Base64 válido") from None
    if not assinatura:
        raise ErroFormato("assinatura vazia")

    return DadosAssinatura(
        bits_chave=int(cabecalho["Key-Bits"]),
        impressao_digital=cabecalho["Key-Fingerprint"],
        nome_arquivo=cabecalho["File-Name"],
        tamanho_arquivo=int(cabecalho["File-Size"]),
        hash_arquivo=bytes.fromhex(cabecalho["File-Digest"]),
        assinatura=assinatura,
    )


# Resultados possíveis da verificação
VALIDA = "ASSINATURA VÁLIDA - arquivo íntegro e autêntico"
ARQUIVO_ALTERADO = "ASSINATURA INVÁLIDA - o arquivo foi modificado após a assinatura"
CHAVE_INCORRETA = "ASSINATURA INVÁLIDA - a chave pública não é a do signatário"
ASSINATURA_CORROMPIDA = "ASSINATURA INVÁLIDA - a assinatura foi corrompida ou forjada"
ESTRUTURA_MALFORMADA = "ASSINATURA INVÁLIDA - arquivo .sig malformado"


def verificar_arquivo(chave_publica, caminho_arquivo, texto_assinatura):
    """Verifica a assinatura de um arquivo. Devolve (valida, resultado, detalhe).

    Passos:
      1. faz o parsing do .sig;
      2. recalcula o SHA3-256 do arquivo recebido;
      3. verifica o RSA-PSS com a chave pública -> ESTA é a decisão;
      4. se falhou, usa o cabeçalho só para explicar o motivo.
    """
    try:
        dados = ler_texto_assinatura(texto_assinatura)
    except ErroFormato as erro:
        return False, ESTRUTURA_MALFORMADA, str(erro)

    hash_atual = sha3_256_de_arquivo(caminho_arquivo)

    if pss_verificar(chave_publica, hash_atual, dados.assinatura):
        return True, VALIDA, f"SHA3-256: {hash_atual.hex()}"

    if hash_atual != dados.hash_arquivo:
        return False, ARQUIVO_ALTERADO, (f"hash registrado: {dados.hash_arquivo.hex()}\n"
                                         f"  hash atual:     {hash_atual.hex()}")
    if dados.impressao_digital != chave_publica.impressao_digital():
        return False, CHAVE_INCORRETA, (f"chave do signatário: {dados.impressao_digital}\n"
                                        f"  chave fornecida:     {chave_publica.impressao_digital()}")
    return False, ASSINATURA_CORROMPIDA, "a verificação RSA-PSS falhou"


# =============================================================================
# 9. DEMONSTRAÇÃO E TESTES DE ADULTERAÇÃO  (Partes IV e V)
# =============================================================================

def titulo(texto):
    print("\n" + "=" * 70 + f"\n{texto}\n" + "=" * 70)


def resumir_hex(dados, tamanho=16):
    h = dados.hex()
    return h if len(h) <= 2 * tamanho else f"{h[:tamanho]}...{h[-tamanho:]} ({len(dados)} bytes)"


def inverter_um_bit(dados, posicao):
    copia = bytearray(dados)
    copia[posicao] ^= 0x01
    return bytes(copia)


def mostrar_verificacao(descricao, resultado):
    valida, mensagem, detalhe = resultado
    print(f"\n[{descricao}]\n{mensagem}\n  {detalhe}")
    return valida


def executar_demonstracao():
    pasta = tempfile.mkdtemp(prefix="demo-rsa-")
    todos_ok = True

    # ---------------------------------------------------------------- Parte I
    titulo("PARTE I - Geração de chaves RSA-2048 com Miller-Rabin")
    print("Miller-Rabin: 561 (Carmichael) ->", teste_miller_rabin(561),
          "| 1729 (Carmichael) ->", teste_miller_rabin(1729),
          "| 2^127 - 1 (primo) ->", teste_miller_rabin(2 ** 127 - 1))
    inicio = time.time()
    alice = gerar_par_de_chaves()
    bob = gerar_par_de_chaves()
    print(f"Dois pares de chaves gerados em {time.time() - inicio:.1f} s")
    print(f"  n: {alice.bits} bits | p e q: {alice.p.bit_length()} bits | e = {alice.e}")
    print(f"  d: {alice.d.bit_length()} bits | impressão digital: {alice.chave_publica().impressao_digital()[:32]}...")
    texto_pub = exportar_chave_publica(alice.chave_publica())
    todos_ok &= importar_chave_publica(texto_pub) == alice.chave_publica()
    todos_ok &= importar_chave_privada(exportar_chave_privada(alice)).d == alice.d
    print("  exportação e importação das chaves: OK")

    # --------------------------------------------------------------- Parte II
    titulo("PARTE II - Cifragem e decifragem RSA-OAEP")
    mensagem = b"segredo"
    cifrado1 = oaep_cifrar(alice.chave_publica(), mensagem)
    cifrado2 = oaep_cifrar(alice.chave_publica(), mensagem)
    print(f"mensagem:   {mensagem!r}")
    print(f"cifrado 1:  {resumir_hex(cifrado1)}")
    print(f"cifrado 2:  {resumir_hex(cifrado2)}")
    print(f"iguais?     {cifrado1 == cifrado2}  (o OAEP é aleatório)")
    decifrado = oaep_decifrar(alice, cifrado1)
    print(f"decifrado:  {decifrado!r}")
    todos_ok &= decifrado == mensagem and cifrado1 != cifrado2
    print(f"tamanho máximo da mensagem: {tamanho_maximo_oaep(alice.chave_publica())} bytes")
    for descricao, tentativa in (
        ("1 bit do cifrado invertido", lambda: oaep_decifrar(alice, inverter_um_bit(cifrado1, 100))),
        ("chave privada errada", lambda: oaep_decifrar(bob, cifrado1)),
        ("rótulo diferente", lambda: oaep_decifrar(alice, cifrado1, b"outro")),
        ("mensagem de 191 bytes", lambda: oaep_cifrar(alice.chave_publica(), b"x" * 191)),
    ):
        try:
            tentativa()
            todos_ok = False
            print(f"  {descricao}: ERRO - deveria ter falhado")
        except (ErroDecifragem, ErroMensagemMuitoLonga) as erro:
            print(f"  {descricao}: recusado -> {erro}")

    # -------------------------------------------------------------- Parte III
    titulo("PARTE III - Assinatura RSA-PSS de um arquivo")
    caminho = os.path.join(pasta, "contrato.txt")
    conteudo = b"Eu, Alice, pago R$ 100,00 ao Bob.\n" * 50
    with open(caminho, "wb") as arquivo:
        arquivo.write(conteudo)
    dados = assinar_arquivo(alice, caminho)
    texto_sig = gerar_texto_assinatura(dados)
    print(texto_sig)
    bloco = inteiro_para_bytes(rsa_operacao_publica(alice.chave_publica(),
                                                    bytes_para_inteiro(dados.assinatura)), 256)
    print(f"bloco recuperado com s^e mod n: {resumir_hex(bloco)}")
    print(f"termina em 0xBC? {bloco[-1] == 0xBC} | contém o hash em claro? {dados.hash_arquivo in bloco}")
    print("=> a assinatura não é o hash cifrado: é o bloco PSS com salt e máscara.")
    todos_ok &= bloco[-1] == 0xBC and dados.hash_arquivo not in bloco

    # --------------------------------------------------------------- Parte IV
    titulo("PARTE IV - Verificação e testes de integridade")
    pub_alice = alice.chave_publica()
    todos_ok &= mostrar_verificacao("arquivo e assinatura originais",
                                    verificar_arquivo(pub_alice, caminho, texto_sig))

    with open(caminho, "wb") as arquivo:
        arquivo.write(inverter_um_bit(conteudo, 10))
    todos_ok &= not mostrar_verificacao("(a) 1 byte do arquivo alterado",
                                        verificar_arquivo(pub_alice, caminho, texto_sig))
    with open(caminho, "wb") as arquivo:
        arquivo.write(conteudo)

    dados_adulterados = ler_texto_assinatura(texto_sig)
    dados_adulterados.assinatura = inverter_um_bit(dados_adulterados.assinatura, 128)
    todos_ok &= not mostrar_verificacao("(b) 1 byte da assinatura alterado",
                                        verificar_arquivo(pub_alice, caminho,
                                                          gerar_texto_assinatura(dados_adulterados)))

    todos_ok &= not mostrar_verificacao("(c) chave pública de outra pessoa",
                                        verificar_arquivo(bob.chave_publica(), caminho, texto_sig))

    bytes_n = bytearray(inteiro_para_bytes(alice.n, 256))
    bytes_n[255] ^= 0x02
    chave_adulterada = ChavePublica(bytes_para_inteiro(bytes_n), alice.e)
    todos_ok &= not mostrar_verificacao("(c) 1 byte do módulo n alterado",
                                        verificar_arquivo(chave_adulterada, caminho, texto_sig))

    todos_ok &= not mostrar_verificacao("arquivo .sig malformado (hash trocado para SHA-1)",
                                        verificar_arquivo(pub_alice, caminho,
                                                          texto_sig.replace("Hash: SHA3-256", "Hash: SHA-1")))

    # ---------------------------------------------------------------- Parte V
    titulo("PARTE V - Por que o RSA sem padding é inseguro")
    n, e, d = alice.n, alice.e, alice.d
    m = bytes_para_inteiro(b"SIM")
    c = potencia_modular(m, e, n)
    print(f"1) Determinístico: cifrar 'SIM' duas vezes dá o mesmo resultado? "
          f"{c == potencia_modular(m, e, n)}")
    print("   -> um atacante pode testar palpites cifrando-os com a chave pública.")
    c_modificado = (c * potencia_modular(2, e, n)) % n
    print(f"2) Maleável: c * 2^e decifra para 2 * m? {potencia_modular(c_modificado, d, n) == 2 * m}")
    m1, m2 = bytes_para_inteiro(b"pago 10"), bytes_para_inteiro(b"x")
    s_forjada = (potencia_modular(m1, d, n) * potencia_modular(m2, d, n)) % n
    print(f"3) Assinatura forjada: s1 * s2 é assinatura válida de m1 * m2? "
          f"{potencia_modular(s_forjada, e, n) == (m1 * m2) % n}")
    print("   -> OAEP e PSS impedem esses ataques com aleatoriedade e estrutura verificável.")

    titulo("RESULTADO: todas as verificações corretas" if todos_ok
           else "RESULTADO: ALGUMA VERIFICAÇÃO FALHOU")
    return 0 if todos_ok else 1


# =============================================================================
# 10. LINHA DE COMANDO
# =============================================================================

def comando_gerar_chaves(args):
    print(f"Gerando chaves RSA-{args.bits}...", file=sys.stderr)
    chave = gerar_par_de_chaves(args.bits)
    salvar_arquivo_texto(args.saida + ".priv", exportar_chave_privada(chave), eh_segredo=True)
    salvar_arquivo_texto(args.saida + ".pub", exportar_chave_publica(chave.chave_publica()))
    print(f"Chave privada: {args.saida}.priv (permissão 0600)")
    print(f"Chave pública: {args.saida}.pub")
    print(f"Impressão digital: {chave.chave_publica().impressao_digital()}")
    return 0


def comando_cifrar(args):
    chave = importar_chave_publica(ler_arquivo_texto(args.chave))
    cifrado = oaep_cifrar(chave, args.mensagem.encode(), args.rotulo.encode())
    texto = base64.b64encode(cifrado).decode()
    if args.saida:
        salvar_arquivo_texto(args.saida, texto + "\n")
        print(f"Texto cifrado ({len(cifrado)} bytes) salvo em {args.saida}")
    else:
        print(texto)
    return 0


def comando_decifrar(args):
    chave = importar_chave_privada(ler_arquivo_texto(args.chave))
    try:
        cifrado = base64.b64decode("".join(ler_arquivo_texto(args.entrada).split()), validate=True)
    except (binascii.Error, ValueError):
        raise ErroDecifragem() from None
    print(oaep_decifrar(chave, cifrado, args.rotulo.encode()).decode("utf-8", errors="replace"))
    return 0


def comando_assinar(args):
    chave = importar_chave_privada(ler_arquivo_texto(args.chave))
    dados = assinar_arquivo(chave, args.arquivo)
    destino = args.saida or args.arquivo + ".sig"
    salvar_arquivo_texto(destino, gerar_texto_assinatura(dados))
    print(f"SHA3-256 do arquivo: {dados.hash_arquivo.hex()}")
    print(f"Assinatura salva em {destino}")
    return 0


def comando_verificar(args):
    chave = importar_chave_publica(ler_arquivo_texto(args.chave))
    valida, mensagem, detalhe = verificar_arquivo(chave, args.arquivo, ler_arquivo_texto(args.assinatura))
    print(f"{mensagem}\n  {detalhe}")
    return 0 if valida else 1


def main():
    parser = argparse.ArgumentParser(description="RSA-OAEP e RSA-PSS com SHA3-256")
    sub = parser.add_subparsers(dest="comando", required=True)

    sub.add_parser("demo", help="demonstração completa das Partes I a V")

    p = sub.add_parser("gerar-chaves", help="gera um par de chaves RSA")
    p.add_argument("--bits", type=int, default=2048)
    p.add_argument("--saida", required=True, help="prefixo dos arquivos .pub e .priv")

    p = sub.add_parser("cifrar", help="cifra uma mensagem curta com RSA-OAEP")
    p.add_argument("--chave", required=True, help="chave PÚBLICA do destinatário")
    p.add_argument("--mensagem", required=True)
    p.add_argument("--rotulo", default="")
    p.add_argument("--saida")

    p = sub.add_parser("decifrar", help="decifra uma mensagem RSA-OAEP")
    p.add_argument("--chave", required=True, help="chave PRIVADA do destinatário")
    p.add_argument("--entrada", required=True)
    p.add_argument("--rotulo", default="")

    p = sub.add_parser("assinar", help="assina um arquivo com RSA-PSS")
    p.add_argument("--chave", required=True, help="chave PRIVADA do signatário")
    p.add_argument("--arquivo", required=True)
    p.add_argument("--saida", help="padrão: <arquivo>.sig")

    p = sub.add_parser("verificar", help="verifica a assinatura de um arquivo")
    p.add_argument("--chave", required=True, help="chave PÚBLICA do signatário")
    p.add_argument("--arquivo", required=True)
    p.add_argument("--assinatura", required=True)

    args = parser.parse_args()
    comandos = {
        "demo": lambda _: executar_demonstracao(),
        "gerar-chaves": comando_gerar_chaves,
        "cifrar": comando_cifrar,
        "decifrar": comando_decifrar,
        "assinar": comando_assinar,
        "verificar": comando_verificar,
    }
    try:
        return comandos[args.comando](args)
    except ErroDecifragem as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 1
    except (ErroRSA, OSError) as erro:
        print(f"erro: {erro}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
