import argparse, sys, unicodedata
from collections import Counter

ALFA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
FREQ = {
    "pt": [14.63, 1.04, 3.88, 4.99, 12.57, 1.02, 1.30, 1.28, 6.18, 0.40, 0.02, 2.78, 4.74,
           5.05, 10.73, 2.52, 1.20, 6.53, 7.81, 4.34, 4.63, 1.67, 0.01, 0.21, 0.01, 0.47],
    "en": [8.167, 1.492, 2.782, 4.253, 12.702, 2.228, 2.015, 6.094, 6.966, 0.153, 0.772, 4.025,
           2.406, 6.749, 7.507, 1.929, 0.095, 5.987, 6.327, 9.056, 2.758, 0.978, 2.360, 0.150,
           1.974, 0.074],
}
IC_IDIOMA = {"pt": 0.0745, "en": 0.0667}
IC_ALEATORIO = 1 / 26


def normalizar(texto):
    return "".join(c for c in unicodedata.normalize("NFD", texto)
                   if unicodedata.category(c) != "Mn")


def vigenere(texto, chave, decifrar=False):
    chave = [ALFA.index(c) for c in normalizar(chave).upper() if c in ALFA]
    if not chave:
        sys.exit("Erro: a chave precisa ter pelo menos uma letra A-Z.")
    saida, j = [], 0
    for c in normalizar(texto):
        if c.upper() in ALFA:
            k = -chave[j % len(chave)] if decifrar else chave[j % len(chave)]
            r = ALFA[(ALFA.index(c.upper()) + k) % 26]
            saida.append(r.lower() if c.islower() else r)
            j += 1
        else:
            saida.append(c)
    return "".join(saida)


def so_letras(texto):
    return "".join(c for c in normalizar(texto).upper() if c in ALFA)


def ic(texto):
    n = len(texto)
    return sum(v * (v - 1) for v in Counter(texto).values()) / (n * (n - 1)) if n > 1 else 0


def qui2(texto, idioma):
    n, cont = len(texto), Counter(texto)
    return sum((cont[l] - f / 100 * n) ** 2 / (f / 100 * n)
               for l, f in zip(ALFA, FREQ[idioma]))


def quebrar(cripto, idioma, tamanho=None, max_tam=20, mostrar=True):
    letras = so_letras(cripto)


    tabela = {m: sum(ic(letras[i::m]) for i in range(m)) / m for m in range(1, max_tam + 1)}
    limiar = IC_ALEATORIO + 0.85 * (max(tabela.values()) - IC_ALEATORIO)
    if tamanho is None:
        tamanho = min(m for m, v in tabela.items() if v >= limiar)


    pos, votos = {}, Counter()
    for i in range(len(letras) - 2):
        pos.setdefault(letras[i:i + 3], []).append(i)
    for p in pos.values():
        for a, b in zip(p, p[1:]):
            votos.update(m for m in range(2, max_tam + 1) if (b - a) % m == 0)


    chave, ranking = "", []
    for i in range(tamanho):
        coset = letras[i::tamanho]
        r = sorted((qui2("".join(ALFA[(ALFA.index(c) - k) % 26] for c in coset), idioma), ALFA[k])
                   for k in range(26))
        chave += r[0][1]
        ranking.append(r[:3])


    claro = vigenere(cripto, chave, decifrar=True)
    ic_final = ic(so_letras(claro))

    if mostrar:
        print(f"\n[1] Tamanho da chave (idioma {idioma}) — IC bruto {ic(letras):.4f}, "
              f"limiar {limiar:.4f}")
        for m, v in tabela.items():
            print(f"    m={m:2d}  IC={v:.4f}  {'█' * int(max(v - 0.03, 0) * 600)}"
                  f"{'  ◀' if m == tamanho else ''}")
        print(f"[2] Kasiski (tamanho:votos): " +
              "  ".join(f"{m}:{v}" for m, v in votos.most_common(6)))
        print(f"[3] Letras da chave — 3 melhores candidatos por posição (letra, χ²):")
        for i, r in enumerate(ranking, 1):
            print(f"    pos {i:2d}: " + "   ".join(f"{l} ({q:7.1f})" for q, l in r))
        print(f"    CHAVE: {chave}")
        print(f"[4] Validação — IC do texto decifrado {ic_final:.4f} "
              f"(esperado ≈ {IC_IDIOMA[idioma]:.4f}) → "
              + ("OK" if ic_final >= 0.06 else "SUSPEITO: tente --tamanho ou outro candidato"))
    return chave, claro, ic_final


def testar():
    ok = vigenere("ATTACKATDAWN", "LEMON") == "LXFOPVEFRNHR"
    print("vetor clássico ATTACKATDAWN+LEMON:", "OK" if ok else "FALHOU")
    msg = "Atenção, General! Reunião às 14h30 no ponto-X."
    ok2 = vigenere(vigenere(msg, "UnB"), "UnB", decifrar=True) == normalizar(msg)
    print("decifrar(cifrar(m)) == m (acentos, pontuação, caixa):", "OK" if ok2 else "FALHOU")
    for idioma, chave in (("pt", "LIBERDADE"), ("en", "CRYPTO")):
        try:
            cripto = open(f"exemplos/criptograma_{idioma}.txt", encoding="utf-8").read()
        except OSError:
            print(f"ataque {idioma}: exemplos/criptograma_{idioma}.txt não encontrado"); continue
        achada = quebrar(cripto, idioma, mostrar=False)[0]
        print(f"ataque {idioma} (chave {chave}):", "OK" if achada == chave else f"FALHOU → {achada}")


def main():
    p = argparse.ArgumentParser(description="Cifra de Vigenère — cifra, decifra e ataca.")
    sub = p.add_subparsers(dest="cmd", required=True)
    for nome in ("cifrar", "decifrar", "atacar"):
        s = sub.add_parser(nome)
        s.add_argument("-t", "--texto"), s.add_argument("-a", "--arquivo")
        s.add_argument("-o", "--saida", help="grava o resultado neste arquivo")
        if nome == "atacar":
            s.add_argument("-i", "--idioma", choices=("pt", "en"), help="omita para detectar")
            s.add_argument("--tamanho", type=int, help="força o tamanho da chave")
            s.add_argument("--max", type=int, default=20)
        else:
            s.add_argument("-c", "--chave", required=True)
    sub.add_parser("testar")
    a = p.parse_args()

    if a.cmd == "testar":
        return testar()
    if a.texto is None and a.arquivo is None:
        sys.exit('Erro: informe -t "texto" ou -a arquivo.txt')
    entrada = a.texto if a.texto is not None else open(a.arquivo, encoding="utf-8").read()

    if a.cmd in ("cifrar", "decifrar"):
        resultado = vigenere(entrada, a.chave, decifrar=(a.cmd == "decifrar"))
    else:
        idiomas = [a.idioma] if a.idioma else ["pt", "en"]

        melhor = min(idiomas, key=lambda i: qui2(so_letras(quebrar(entrada, i, a.tamanho, a.max, False)[1]), i))
        chave, resultado, _ = quebrar(entrada, melhor, a.tamanho, a.max)
        print(f"\nTEXTO DECIFRADO (chave {chave}):\n")

    if a.saida:
        open(a.saida, "w", encoding="utf-8").write(resultado)
        print(f"[ok] gravado em {a.saida}")
    else:
        print(resultado if len(resultado) <= 2000 else resultado[:2000] + "\n[...]")


if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        pass
