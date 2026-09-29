# Formatos de arquivo definidos pelo grupo

## 1. Chaves (`.pub` / `.priv`)

Envelope de texto ASCII no estilo PEM:

```
-----BEGIN RSASEG PUBLIC KEY-----
eyJiaXRzIjoyMDQ4LCJlIjoiMTAwMDEiLCJmb3JtYXRvIjoicnNhc2VnLXYxIiwi
...
-----END RSASEG PUBLIC KEY-----
```

O conteúdo entre os delimitadores é o **Base64** (linhas de 64 caracteres) de um **JSON canônico** (chaves em ordem alfabética, sem espaços, UTF‑8).

Chave pública:

```json
{"bits":2048,"e":"10001","formato":"rsaseg-v1","n":"c3a1…","tipo":"publica"}
```

Chave privada (rótulo `RSASEG PRIVATE KEY`):

```json
{"bits":2048,"d":"…","dp":"…","dq":"…","e":"10001","formato":"rsaseg-v1",
 "n":"…","p":"…","q":"…","qinv":"…","tipo":"privada"}
```

| Campo | Significado |
|---|---|
| `formato` | sempre `rsaseg-v1` |
| `tipo` | `publica` ou `privada` |
| `bits` | tamanho do módulo em bits (conferido na importação) |
| `n`, `e` | módulo e expoente público |
| `d` | expoente privado, `e⁻¹ mod mmc(p−1, q−1)` |
| `p`, `q` | fatores primos, com `p > q` |
| `dp`, `dq` | `d mod (p−1)`, `d mod (q−1)` (CRT) |
| `qinv` | `q⁻¹ mod p` (CRT) |

Todos os inteiros são **hexadecimais minúsculos sem prefixo** (regex `^[0-9a-f]+$`).

Regras de importação: delimitadores exatos, Base64 estrito, conjunto de campos exato (sem campos extras nem faltando), `bits` coerente com `n`, módulo de pelo menos 2048 bits, `e` ímpar com 2¹⁶ < e < 2²⁵⁶. Para chaves privadas, também são conferidos `n = p·q`, a primalidade de `p` e `q`, `e·d ≡ 1 (mod λ(n))` e os parâmetros do CRT.

**Impressão digital:** `SHA3-256("rsaseg-pub" ‖ I2OSP(n, k) ‖ I2OSP(e, ⌈bits(e)/8⌉))`, em hexadecimal.

## 2. Texto cifrado OAEP (`.enc`)

Uma linha com o Base64 dos `k` bytes (256 para RSA‑2048) produzidos por RSAES‑OAEP‑ENCRYPT (SHA3‑256, MGF1‑SHA3‑256, rótulo opcional, vazio por padrão).

## 3. Estrutura assinada (`.sig`) — assinatura destacada

```
-----BEGIN RSASEG SIGNATURE-----
Version: 1
Algorithm: RSASSA-PSS
Hash: SHA3-256
MGF: MGF1-SHA3-256
Salt-Length: 32
Key-Bits: 2048
Key-Fingerprint: <64 hex>
File-Name: contrato.txt
File-Size: 34
File-Digest: <64 hex = SHA3-256 do arquivo>
Signature:
<Base64 da assinatura de k bytes, linhas de 64 caracteres>
-----END RSASEG SIGNATURE-----
```

Parsing (`assinatura_arquivo.analisar`): os delimitadores são obrigatórios; cada linha de cabeçalho tem a forma `Campo: valor`; campos desconhecidos, duplicados ou ausentes são rejeitados; `Version`, `Algorithm`, `Hash` e `MGF` precisam ter exatamente os valores acima; campos numéricos são decimais; os campos hexadecimais têm 64 dígitos minúsculos; a assinatura é Base64 estrito.

Verificação (`assinatura_arquivo.verificar_arquivo`):

1. faz o parsing da estrutura (se falhar: `ESTRUTURA_INVALIDA`);
2. exige `Salt-Length = 32` (política do verificador);
3. **recalcula** o SHA3‑256 do arquivo (o `File-Digest` registrado não é usado na decisão);
4. executa RSASSA‑PSS‑VERIFY com a chave pública fornecida;
5. se for válida: `VALIDA`. Caso contrário, o diagnóstico usa os metadados: digest ou tamanho diferente → `ARQUIVO_ALTERADO`; impressão digital diferente → `CHAVE_INCORRETA`; demais casos → `ASSINATURA_INVALIDA`.
