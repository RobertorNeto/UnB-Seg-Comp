"""Hierarquia de exceções do projeto.

Todas as falhas previsíveis (entrada inválida, chave corrompida, texto cifrado
adulterado, estrutura de assinatura malformada) são sinalizadas com subclasses
de ``ErroRSA``, para que a CLI e os testes possam tratá-las de forma segura e
uniforme, sem vazar detalhes internos.
"""


class ErroRSA(Exception):
    """Erro base de toda a biblioteca."""


class ErroParametro(ErroRSA, ValueError):
    """Parâmetro inválido (tamanho, intervalo, tipo)."""


class MensagemMuitoLonga(ErroRSA):
    """Mensagem excede o limite do esquema (RFC 8017: 'message too long')."""


class ErroDecifragem(ErroRSA):
    """Falha genérica de decifragem OAEP.

    Propositalmente usa UMA única mensagem para qualquer causa (padding,
    rótulo, byte inicial, tamanho), evitando oráculos de padding
    (ataque de Manger).
    """

    def __init__(self, msg: str = "falha na decifragem") -> None:
        super().__init__(msg)


class ErroFormato(ErroRSA):
    """Arquivo de chave ou de assinatura malformado."""


class ErroChave(ErroRSA):
    """Chave inconsistente ou fora da política de segurança."""
