# Parte V — Análise de segurança

## 0. Cifragem × assinatura: dois usos distintos do RSA

A mesma permutação com alçapão `x ↦ x^e mod n` é usada de dois jeitos que **não são simétricos**:

| | Cifragem (RSAES-OAEP) | Assinatura (RSASSA-PSS) |
|---|---|---|
| Objetivo | confidencialidade | autenticidade + integridade + não repúdio |
| Quem usa a chave pública | **remetente**, para cifrar | **qualquer verificador** |
| Quem usa a chave privada | **destinatário**, para decifrar | **signatário**, para assinar |
| Primitivas (RFC 8017) | RSAEP / RSADP | RSASP1 / RSAVP1 |
| Codificação | EME-OAEP (reversível, recupera M) | EMSA-PSS (não reversível, só verifica) |
| Entrada | a própria mensagem curta (≤ 190 B em RSA-2048) | o digest SHA3-256 do arquivo |
| Saída de erro | uma única "falha na decifragem" | booleano válido/inválido |

No código isso aparece de forma explícita: `oaep.py` só chama `rsaep`/`rsadp`; `pss.py` só chama `rsasp1`/`rsavp1`. Por isso a frase "assinar é cifrar o hash com a chave privada" é **incorreta**: ela só é verdadeira (de maneira aproximada) para o RSA de livro‑texto, que é inseguro, e não se generaliza para outros esquemas (DSA, ECDSA e Ed25519 não têm "cifragem" nenhuma). Uma assinatura não precisa esconder nada — ela precisa ser **impossível de forjar**; a cifragem precisa **esconder** e resistir a textos cifrados escolhidos. São requisitos de segurança diferentes (EUF‑CMA × IND‑CCA2), e cada um exige uma codificação própria.

## 1. Por que RSA sem padding seguro não deve ser usado diretamente

O RSA "cru" (`c = m^e mod n`, `s = m^d mod n`) é apenas uma permutação de mão única; ele não é um esquema de cifragem nem de assinatura seguro. Problemas (vários demonstrados em `demo.py`):

1. **Determinismo.** A mesma mensagem sempre gera o mesmo texto cifrado. Um atacante que conhece a chave pública pode cifrar palpites ("SIM"/"NÃO", um CPF, um valor) e comparar. Logo não há segurança semântica (IND‑CPA).
2. **Maleabilidade / homomorfismo multiplicativo.** `Enc(m1)·Enc(m2) = Enc(m1·m2) mod n`. Um atacante transforma `c` em `c·2^e`, que decifra para `2m`, sem conhecer `m`. Isso permite ataques de texto cifrado escolhido (quebra IND‑CCA2).
3. **Mensagens pequenas e expoente pequeno.** Se `m^e < n` (ex.: `e = 3` e `m` curto), então `c = m^e` sobre os inteiros e basta tirar a raiz cúbica. Com a mesma mensagem enviada a `e` destinatários, o ataque de difusão de Håstad (via CRT) recupera `m`.
4. **Estrutura algébrica explorável.** Ataques de Coppersmith/Franklin‑Reiter sobre mensagens relacionadas ou parcialmente conhecidas.
5. **Falsificação de assinaturas.** Com o RSA cru: (a) *falsificação existencial sem mensagem*: escolhe‑se `s` qualquer e `m = s^e mod n` é uma "mensagem assinada"; (b) *propriedade multiplicativa*: de `s1` e `s2` obtém‑se `s1·s2`, assinatura válida de `m1·m2`; (c) o ataque de *blinding* obtém a assinatura de uma mensagem que a vítima nunca assinaria, pedindo que ela assine `m·r^e`.
6. **Paddings antigos também falham quando mal usados.** O PKCS#1 v1.5 para cifragem sofre o ataque do oráculo de padding de Bleichenbacher (1998) e suas variantes (ROBOT, 2017). Assinaturas v1.5 com verificação descuidada sofreram a falsificação de Bleichenbacher (2006) com `e = 3`.

Conclusão: o RSA precisa de uma **codificação aleatorizada e com redundância verificável**, com prova de segurança — OAEP para cifragem e PSS para assinatura.

## 2. A função do OAEP na cifragem

O OAEP (Bellare–Rogaway, 1994) é uma rede de Feistel de duas rodadas com as funções de máscara `G = H = MGF1(SHA3-256)`:

```
DB         = lHash || 00…00 || 01 || M
maskedDB   = DB   ⊕ MGF1(seed)
maskedSeed = seed ⊕ MGF1(maskedDB)
EM         = 00 || maskedSeed || maskedDB
```

O que cada parte faz:

- **`seed` aleatório (32 bytes)** torna a cifragem **probabilística**: a mesma mensagem produz cifrados diferentes a cada vez, eliminando o ataque de dicionário do item 1.1.
- **Mistura "tudo ou nada"**: cada bit de `EM` depende de toda a `seed` e de todo o `DB`. Sem inverter o RSA por completo o atacante não obtém nenhum bit útil de `M`, e alterar qualquer bit do texto cifrado embaralha todo o bloco decifrado.
- **Redundância verificável** (`lHash`, os zeros de `PS`, o separador `0x01` e o byte inicial `0x00`): um texto cifrado forjado ou manipulado (item 1.2) quase certamente não produz uma estrutura válida e é rejeitado. É isso que dá **consciência do texto claro** (*plaintext awareness*) e leva à segurança **IND‑CCA2** no modelo do oráculo aleatório (Fujisaki–Okamoto–Pointcheval–Stern, 2001).
- **Rótulo (`label`)** permite vincular o texto cifrado a um contexto; um rótulo diferente faz a decifragem falhar.
- **Mensagem sempre "grande"**: `EM` ocupa praticamente todo o módulo, o que anula os ataques de raiz `e`‑ésima e de Håstad.

**Cuidado de implementação (Manger, 2001):** se a decifragem revelar *qual* verificação falhou (por exemplo, "primeiro byte ≠ 0" × "lHash incorreto"), ou demorar tempos diferentes, surge um oráculo que recupera a mensagem com cerca de 1000 consultas. Em `oaep.py` todas as verificações são executadas antes da decisão, sem desvios dependentes dos dados, e qualquer falha gera a mesma exceção, `ErroDecifragem("falha na decifragem")`. Além disso a operação privada usa *blinding* (contra ataques de temporização) e confere o resultado do CRT (contra ataques de falha de Boneh–DeMillo–Lipton).

## 3. A função do PSS na assinatura digital

O PSS (Bellare–Rogaway, 1996) codifica o digest `mHash = SHA3-256(arquivo)` assim:

```
M'       = 00×8 || mHash || salt
H        = SHA3-256(M')
DB       = 00…00 || 01 || salt
maskedDB = DB ⊕ MGF1(H)          (bit mais alto zerado)
EM       = maskedDB || H || BC
s        = EM^d mod n
```

Funções:

- **Salt aleatório (32 bytes)**: a assinatura é **probabilística**. Assinar duas vezes o mesmo arquivo gera assinaturas diferentes, ambas válidas. O salt é o que permite uma **redução de segurança justa (tight)** ao problema RSA no modelo do oráculo aleatório; no esquema determinístico (FDH, v1.5) a redução perde um fator proporcional ao número de assinaturas emitidas.
- **Destrói a estrutura multiplicativa**: `EM` é essencialmente pseudoaleatório e cheio de redundância (`0xBC`, `0x01`, zeros, `H = Hash(M')`). O produto de duas assinaturas válidas não produz um `EM` válido, e escolher `s` ao acaso e calcular `s^e` quase nunca gera uma codificação consistente. Os ataques do item 1.5 deixam de funcionar.
- **Vinculação ao hash**: o verificador recalcula `H' = Hash(00×8 || mHash || salt)` a partir do salt recuperado e compara com `H`. Qualquer alteração no arquivo (outro `mHash`) ou na assinatura quebra a igualdade.
- **Verificação estrita**: `pss.py` confere o tamanho exato da assinatura, o intervalo `s < n`, os bits mais altos zerados, o trailer `0xBC`, o bloco de zeros e o separador `0x01`, e só então compara os hashes (com `hmac.compare_digest`). O parser da estrutura assinada rejeita parâmetros diferentes dos implementados, para evitar ataques de "confusão de algoritmo".

É por isso que o enunciado proíbe a "cifragem do hash": `hash^d mod n` herda todas as fraquezas do RSA cru (sem aleatoriedade, sem redundância verificável, maleável). O teste `test_nao_e_cifragem_do_hash` mostra que o bloco recuperado por `s^e mod n` não contém o hash em claro, e sim a codificação EMSA‑PSS.

## 4. RSA‑PSS × Ed25519

| Critério | RSA‑PSS‑2048 (este trabalho) | Ed25519 (EdDSA, RFC 8032) |
|---|---|---|
| Problema difícil | fatoração / problema RSA | logaritmo discreto na curva Edwards25519 |
| Nível de segurança | ≈ 112 bits (128 bits exige RSA‑3072) | ≈ 128 bits |
| Chave pública | 256 bytes (+ `e`) | 32 bytes |
| Chave privada | ~1,2 KB (n, d, p, q, CRT) | 32 bytes (semente) |
| Assinatura | 256 bytes | 64 bytes |
| Geração de chaves | lenta (busca de primos, Miller‑Rabin) | instantânea (32 bytes aleatórios + hash) |
| Assinar | lento (exponenciação de 2048 bits) | muito rápido |
| Verificar | muito rápido (e = 65537) | rápido (um pouco mais lento que o RSA) |
| Aleatoriedade ao assinar | precisa de salt aleatório (PSS) | **determinística**: nonce = H(chave ‖ mensagem), sem risco de RNG ruim vazar a chave (caso ECDSA/PS3) |
| Complexidade de implementação | alta: padding, MGF, CRT, blinding, verificações estritas | menor e com parâmetros fixos; projetada para tempo constante |
| Armadilhas típicas | padding errado, oráculos, falhas no CRT, primos fracos | validação de pontos/maleabilidade em implementações antigas, cofator |
| Cifragem com o mesmo tipo de chave | sim (RSA‑OAEP) | não: Ed25519 só assina; para acordo de chaves usa‑se X25519 |
| Computação quântica | quebrado pelo algoritmo de Shor | também quebrado por Shor |
| Adoção | legado amplo (PKI, X.509, TLS antigo) | SSH, TLS 1.3, Signal, Git, DNSSEC; aprovado no FIPS 186‑5 |

**Resumo:** Ed25519 oferece segurança igual ou maior com chaves e assinaturas cerca de 8× menores, assinatura mais rápida e muito menos espaço para erros de implementação, porque não existe um "padding" a ser feito corretamente. O RSA‑PSS continua relevante pela compatibilidade com a PKI existente, pela verificação muito barata e por permitir, com o mesmo tipo de chave, também a cifragem (OAEP). Nenhum dos dois resiste a computadores quânticos; a migração de longo prazo é para esquemas pós‑quânticos como ML‑DSA (FIPS 204) e SLH‑DSA (FIPS 205).

## 5. Limitações conhecidas desta implementação

- Python não garante tempo constante nas operações com inteiros grandes. Mitigamos com *blinding* e com a decifragem OAEP livre de desvios dependentes dos dados, mas a implementação é didática e não substitui bibliotecas auditadas.
- A chave privada é armazenada em claro (com permissão 0600). Em produção ela seria protegida por senha (PBKDF2/scrypt + cifra autenticada) ou mantida em HSM.
- O OAEP cifra apenas mensagens curtas (≤ 190 bytes). Para arquivos seria usada cifragem híbrida: OAEP protegendo uma chave AES‑GCM.
- Os metadados da estrutura `.sig` (nome, tamanho, impressão digital) **não são autenticados**. Eles servem apenas para diagnóstico; a decisão de validade depende exclusivamente da verificação PSS sobre o digest recalculado.
- A impressão digital da chave não substitui uma infraestrutura de confiança (certificados). O verificador precisa obter a chave pública do signatário por um canal autêntico.
