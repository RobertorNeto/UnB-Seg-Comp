"""rsaseg — Sistema de Assinatura Digital e Verificação Segura de Arquivos.

Implementação didática (sem OpenSSL) de:
  * geração de chaves RSA >= 2048 bits com Miller-Rabin   (primos, chaves)
  * RSAES-OAEP  + MGF1 com SHA3-256 para cifragem          (oaep)
  * RSASSA-PSS  + MGF1 com SHA3-256 para assinatura        (pss)
  * estrutura de assinatura de arquivos e verificação      (assinatura_arquivo)
"""

from . import aritmetica, assinatura_arquivo, chaves, hashing, oaep, primitivas, primos, pss
from .erros import ErroChave, ErroDecifragem, ErroFormato, ErroParametro, ErroRSA, MensagemMuitoLonga

__version__ = "1.0.0"

__all__ = [
    "aritmetica", "assinatura_arquivo", "chaves", "hashing", "oaep", "primitivas", "primos", "pss",
    "ErroChave", "ErroDecifragem", "ErroFormato", "ErroParametro", "ErroRSA", "MensagemMuitoLonga",
]
