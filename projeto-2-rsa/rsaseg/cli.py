"""Interface de linha de comando.

    python -m rsaseg gerar-chaves --saida chaves/alice
    python -m rsaseg info        --chave chaves/alice.pub
    python -m rsaseg cifrar      --chave chaves/alice.pub  --mensagem "segredo" --saida msg.enc
    python -m rsaseg decifrar    --chave chaves/alice.priv --entrada msg.enc
    python -m rsaseg assinar     --chave chaves/alice.priv --arquivo doc.pdf
    python -m rsaseg verificar   --chave chaves/alice.pub  --arquivo doc.pdf --assinatura doc.pdf.sig

Códigos de saída: 0 = sucesso / assinatura válida; 1 = assinatura inválida
ou falha de decifragem; 2 = erro de uso/entrada.
"""

import argparse
import base64
import binascii
import sys
import time

from . import assinatura_arquivo as af
from . import chaves as ch
from . import oaep
from .erros import ErroDecifragem, ErroRSA


def _cmd_gerar(a):
    t0 = time.time()
    print(f"Gerando par de chaves RSA-{a.bits} (Miller-Rabin)...", file=sys.stderr)
    priv = ch.gerar_par_chaves(a.bits)
    ch.salvar_texto(a.saida + ".priv", ch.exportar_privada(priv), privado=True)
    ch.salvar_texto(a.saida + ".pub", ch.exportar_publica(priv.publica()))
    print(f"Chave privada: {a.saida}.priv  (permissão 0600)")
    print(f"Chave pública: {a.saida}.pub")
    print(f"Impressão digital: {priv.publica().impressao_digital()}")
    print(f"Tempo: {time.time() - t0:.1f}s", file=sys.stderr)
    return 0


def _carregar_pub(caminho):
    return ch.importar_publica(ch.ler_texto(caminho))


def _carregar_priv(caminho):
    return ch.importar_privada(ch.ler_texto(caminho))


def _cmd_info(a):
    texto = ch.ler_texto(a.chave)
    if "PRIVATE" in texto:
        k = ch.importar_privada(texto).publica()
        print("Tipo: privada (consistência validada)")
    else:
        k = ch.importar_publica(texto)
        print("Tipo: pública")
    print(f"Bits: {k.bits}\ne: {k.e}\nImpressão digital (SHA3-256): {k.impressao_digital()}")
    print(f"Tamanho máximo de mensagem OAEP: {oaep.tamanho_maximo_mensagem(k)} bytes")
    return 0


def _cmd_cifrar(a):
    pub = _carregar_pub(a.chave)
    if a.mensagem is not None:
        msg = a.mensagem.encode("utf-8")
    else:
        with open(a.entrada, "rb") as f:
            msg = f.read()
    c = oaep.cifrar(pub, msg, a.rotulo.encode("utf-8"))
    b64 = base64.b64encode(c).decode("ascii")
    if a.saida:
        with open(a.saida, "w", encoding="ascii") as f:
            f.write(b64 + "\n")
        print(f"Texto cifrado ({len(c)} bytes) gravado em {a.saida} (Base64)")
    else:
        print(b64)
    return 0


def _cmd_decifrar(a):
    priv = _carregar_priv(a.chave)
    with open(a.entrada, "r", encoding="ascii", errors="strict") as f:
        conteudo = "".join(f.read().split())
    try:
        c = base64.b64decode(conteudo, validate=True)
    except (binascii.Error, ValueError):
        raise ErroDecifragem() from None
    m = oaep.decifrar(priv, c, a.rotulo.encode("utf-8"))
    if a.saida:
        with open(a.saida, "wb") as f:
            f.write(m)
        print(f"Mensagem ({len(m)} bytes) gravada em {a.saida}")
    else:
        sys.stdout.write(m.decode("utf-8", errors="replace") + "\n")
    return 0


def _cmd_assinar(a):
    priv = _carregar_priv(a.chave)
    sig = af.assinar_arquivo(priv, a.arquivo)
    destino = a.saida or (a.arquivo + ".sig")
    with open(destino, "w", encoding="utf-8") as f:
        f.write(sig.serializar())
    print(f"Arquivo assinado. Digest SHA3-256: {sig.digest.hex()}")
    print(f"Assinatura (Base64) gravada em {destino}")
    return 0


def _cmd_verificar(a):
    pub = _carregar_pub(a.chave)
    with open(a.assinatura, "r", encoding="utf-8", errors="replace") as f:
        texto = f.read()
    r = af.verificar_arquivo(pub, a.arquivo, texto)
    print(r)
    return 0 if r.valida else 1


def construir_parser():
    p = argparse.ArgumentParser(prog="rsaseg", description="RSA-OAEP / RSA-PSS com SHA3-256")
    sub = p.add_subparsers(dest="comando", required=True)

    g = sub.add_parser("gerar-chaves", help="gera par de chaves RSA")
    g.add_argument("--bits", type=int, default=2048)
    g.add_argument("--saida", required=True, help="prefixo dos arquivos (.pub/.priv)")
    g.set_defaults(func=_cmd_gerar)

    i = sub.add_parser("info", help="mostra informações e valida uma chave")
    i.add_argument("--chave", required=True)
    i.set_defaults(func=_cmd_info)

    c = sub.add_parser("cifrar", help="cifra mensagem curta com RSA-OAEP")
    c.add_argument("--chave", required=True, help="chave PÚBLICA do destinatário")
    grp = c.add_mutually_exclusive_group(required=True)
    grp.add_argument("--mensagem")
    grp.add_argument("--entrada", help="arquivo pequeno a cifrar")
    c.add_argument("--rotulo", default="", help="rótulo OAEP (label), opcional")
    c.add_argument("--saida")
    c.set_defaults(func=_cmd_cifrar)

    d = sub.add_parser("decifrar", help="decifra texto cifrado RSA-OAEP (Base64)")
    d.add_argument("--chave", required=True, help="chave PRIVADA do destinatário")
    d.add_argument("--entrada", required=True)
    d.add_argument("--rotulo", default="")
    d.add_argument("--saida")
    d.set_defaults(func=_cmd_decifrar)

    s = sub.add_parser("assinar", help="assina arquivo com RSA-PSS")
    s.add_argument("--chave", required=True, help="chave PRIVADA do signatário")
    s.add_argument("--arquivo", required=True)
    s.add_argument("--saida", help="padrão: <arquivo>.sig")
    s.set_defaults(func=_cmd_assinar)

    v = sub.add_parser("verificar", help="verifica assinatura RSA-PSS de arquivo")
    v.add_argument("--chave", required=True, help="chave PÚBLICA do signatário")
    v.add_argument("--arquivo", required=True)
    v.add_argument("--assinatura", required=True)
    v.set_defaults(func=_cmd_verificar)
    return p


def main(argv=None) -> int:
    args = construir_parser().parse_args(argv)
    try:
        return args.func(args)
    except ErroDecifragem as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 1
    except (ErroRSA, OSError, UnicodeDecodeError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2
