#!/usr/bin/env python3
"""Demonstração completa para a apresentação: python3 demo.py

Percorre as Partes I a V do enunciado, mostrando cada etapa no terminal.
"""

import os
import tempfile
import time

from rsaseg import chaves as ch
from rsaseg import oaep
from rsaseg.aritmetica import exp_modular, i2osp, os2ip
from rsaseg.assinatura_arquivo import analisar, assinar_arquivo, verificar_arquivo
from rsaseg.erros import ErroDecifragem
from rsaseg.primitivas import rsavp1


def titulo(t):
    print("\n" + "=" * 72 + f"\n{t}\n" + "=" * 72)


def curto(b: bytes, n=24):
    h = b.hex()
    return h if len(h) <= 2 * n else f"{h[:n]}…{h[-n:]} ({len(b)} bytes)"


def main():
    tmp = tempfile.mkdtemp(prefix="rsaseg-demo-")

    titulo("PARTE I — Geração de chaves RSA-2048 (Miller-Rabin)")
    t0 = time.time()
    alice = ch.gerar_par_chaves(2048)
    bob = ch.gerar_par_chaves(2048)
    print(f"2 pares gerados em {time.time() - t0:.1f}s")
    print(f"n  : {alice.bits} bits   e = {alice.e}")
    print(f"p,q: {alice.p.bit_length()} bits cada")
    print(f"d  : {alice.d.bit_length()} bits (d = e^-1 mod mmc(p-1, q-1))")
    print(f"impressão digital: {alice.publica().impressao_digital()}")
    pub_txt = ch.exportar_publica(alice.publica())
    print("\nChave pública exportada:\n" + "\n".join(pub_txt.splitlines()[:3]) + "\n   ...")
    assert ch.importar_publica(pub_txt) == alice.publica()
    assert ch.importar_privada(ch.exportar_privada(alice)).d == alice.d
    print("Importação/exportação: OK (com validação de consistência)")

    titulo("PARTE II — Cifragem RSA-OAEP (SHA3-256 + MGF1)")
    msg = "Chave de sessão AES: 3f9a…  (mensagem curta)".encode()
    c1 = oaep.cifrar(alice.publica(), msg)
    c2 = oaep.cifrar(alice.publica(), msg)
    print(f"mensagem       : {msg!r}")
    print(f"cifrado #1     : {curto(c1)}")
    print(f"cifrado #2     : {curto(c2)}")
    print(f"iguais?        : {c1 == c2}  (OAEP é probabilístico)")
    print(f"decifrado      : {oaep.decifrar(alice, c1)!r}")
    print(f"limite         : {oaep.tamanho_maximo_mensagem(alice.publica())} bytes")
    ruim = bytearray(c1); ruim[100] ^= 1
    for nome, entrada, chave in (("1 bit alterado", bytes(ruim), alice), ("chave errada", c1, bob)):
        try:
            oaep.decifrar(chave, entrada)
        except ErroDecifragem as exc:
            print(f"{nome:15}: rejeitado -> '{exc}'")

    titulo("PARTE III — Assinatura RSA-PSS de arquivo")
    arq = os.path.join(tmp, "contrato.txt")
    with open(arq, "w", encoding="utf-8") as f:
        f.write("Eu, Alice, pago 100 reais ao Bob.\n")
    sig = assinar_arquivo(alice, arq)
    sig_txt = sig.serializar()
    with open(arq + ".sig", "w") as f:
        f.write(sig_txt)
    print(f"SHA3-256 do arquivo: {sig.digest.hex()}")
    print(sig_txt)
    em = i2osp(rsavp1(alice.publica(), os2ip(sig.assinatura)), 256)
    print(f"EM recuperado (s^e mod n): {curto(em)}")
    print(f"termina em 0xBC? {em[-1] == 0xBC} | contém o hash em claro? {sig.digest in em}")
    print("=> não é 'cifragem do hash': é EMSA-PSS com salt aleatório + máscara MGF1.")

    titulo("PARTE IV — Verificação e testes de integridade")
    print("[original]", verificar_arquivo(alice.publica(), arq, sig_txt), sep="\n")

    with open(arq, "rb") as f:
        dados = bytearray(f.read())
    dados[20] ^= 0x01  # "100" -> "000"? altera 1 byte
    with open(arq, "wb") as f:
        f.write(dados)
    print("\n[a) 1 byte do arquivo alterado]", verificar_arquivo(alice.publica(), arq, sig_txt), sep="\n")
    dados[20] ^= 0x01
    with open(arq, "wb") as f:
        f.write(dados)

    s = analisar(sig_txt)
    b = bytearray(s.assinatura); b[128] ^= 0x01; s.assinatura = bytes(b)
    print("\n[b) 1 byte da assinatura alterado]", verificar_arquivo(alice.publica(), arq, s.serializar()), sep="\n")

    print("\n[c) chave pública de outra pessoa]", verificar_arquivo(bob.publica(), arq, sig_txt), sep="\n")
    nb = bytearray(alice.n.to_bytes(256, "big")); nb[255] ^= 0x02
    adulterada = ch.ChavePublica(int.from_bytes(nb, "big"), alice.e)
    print("\n[c) 1 byte do módulo n alterado]", verificar_arquivo(adulterada, arq, sig_txt), sep="\n")

    titulo("PARTE V — Por que RSA sem padding é inseguro (demonstração)")
    pub = alice.publica()
    m = os2ip(b"SIM")
    print(f"1) Determinismo: Enc('SIM') == Enc('SIM')? {exp_modular(m, pub.e, pub.n) == exp_modular(m, pub.e, pub.n)}")
    print("   -> quem vê o cifrado pode testar palpites ('SIM'/'NAO') cifrando-os com a chave pública.")
    c = exp_modular(m, pub.e, pub.n)
    c_mal = (c * exp_modular(2, pub.e, pub.n)) % pub.n
    m_mal = exp_modular(c_mal, alice.d, alice.n)
    print(f"2) Maleabilidade: c' = c * 2^e decifra para 2*m? {m_mal == 2 * m}")
    m1, m2 = os2ip(b"pago 10"), os2ip(b"x")
    s1, s2 = exp_modular(m1, alice.d, alice.n), exp_modular(m2, alice.d, alice.n)
    forjada = (s1 * s2) % alice.n
    print(f"3) Falsificação de assinatura sem padding: s1*s2 é assinatura válida de m1*m2? "
          f"{exp_modular(forjada, pub.e, pub.n) == (m1 * m2) % pub.n}")
    print("   -> PSS impede isso: a verificação exige a estrutura EMSA-PSS (0xBC, 0x01, H(M')).")
    print("\nDetalhes em docs/analise_seguranca.md")
    print(f"\nArquivos de demonstração em: {tmp}")


if __name__ == "__main__":
    main()
