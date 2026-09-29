# CIC0201 — Projeto 2
## Sistema de Assinatura Digital e Verificação Segura de Arquivos (RSA-OAEP e RSA-PSS sobre SHA3-256)

Implementação em **Python 3.8+** (sem OpenSSL e sem dependências externas) de:

- geração de chaves **RSA-2048** com primos obtidos pelo teste de **Miller-Rabin**;
- **RSA-OAEP** para cifragem, com SHA3-256 e MGF1;
- **RSA-PSS** para assinatura, com SHA3-256, MGF1 e salt;
- uma estrutura de assinatura de arquivos em Base64, com verificação de integridade.

**Daniel de Oliveira Morais** (242042396) · **Davi Bragança e Silva** (242001473) · **Roberto Ribeiro Correa de Oliveira Neto** (242009936)

Profa. Priscila Solís Barreto — Departamento de Ciência da Computação, UnB

## Versão em arquivo único (para a apresentação)

[`rsa_assinatura.py`](rsa_assinatura.py) reúne todo o sistema em um só arquivo, com seções numeradas na ordem do enunciado (aritmética, Miller-Rabin, chaves, SHA3/MGF1, RSA básico, OAEP, PSS, arquivo `.sig`, demonstração e CLI). Os formatos de chave e de assinatura são os mesmos do pacote `rsaseg/`.

```bash
python3 rsa_assinatura.py demo        # Partes I a V, incluindo os testes (a), (b) e (c)
python3 rsa_assinatura.py --help      # comandos: gerar-chaves, cifrar, decifrar, assinar, verificar
```

## Estrutura

```
rsaseg/
  aritmetica.py          mdc, Euclides estendido, inverso modular, exponenciação modular, I2OSP/OS2IP
  primos.py              Miller-Rabin e geração de primos           (Parte I)
  chaves.py              geração, validação, importação/exportação  (Parte I)
  primitivas.py          RSAEP/RSADP/RSASP1/RSAVP1 (CRT + blinding)
  hashing.py             SHA3-256 (hashlib) e MGF1                  (Partes II/III)
  oaep.py                RSAES-OAEP                                 (Parte II)
  pss.py                 RSASSA-PSS                                 (Parte III)
  assinatura_arquivo.py  estrutura .sig, parsing e verificação      (Parte IV)
  cli.py                 interface de linha de comando
tests/                   63 testes unitários (unittest)
docs/analise_seguranca.md   Parte V
docs/formatos.md            formatos de chave, texto cifrado e assinatura
rsa_assinatura.py        versão em arquivo único (apresentação)
demo.py                  roteiro de demonstração para a apresentação
exemplos/                arquivo de exemplo
relatorio.pdf            relatório técnico
apresentacao_rsa.pptx    slides da apresentação
```

## Execução

Não há dependências. Basta ter Python 3.8 ou superior (`hashlib.sha3_256` e `secrets` fazem parte da biblioteca padrão).

```bash
# demonstração completa (Partes I a V)
python3 demo.py

# gerar chaves (cria alice.pub e alice.priv, esta com permissão 0600)
python3 -m rsaseg gerar-chaves --saida alice
python3 -m rsaseg info --chave alice.pub

# cifragem e decifragem OAEP (mensagens de até 190 bytes)
python3 -m rsaseg cifrar   --chave alice.pub  --mensagem "segredo" --saida msg.enc
python3 -m rsaseg decifrar --chave alice.priv --entrada msg.enc

# assinatura e verificação PSS
python3 -m rsaseg assinar   --chave alice.priv --arquivo exemplos/contrato.txt
python3 -m rsaseg verificar --chave alice.pub  --arquivo exemplos/contrato.txt \
                            --assinatura exemplos/contrato.txt.sig
```

Códigos de saída: `0` = sucesso ou assinatura válida; `1` = assinatura inválida ou falha de decifragem; `2` = erro de entrada (arquivo inexistente, chave malformada, mensagem longa demais).

## Testes

```bash
python3 -m unittest discover -s tests -t . -v
```

O teste **adicional** de interoperabilidade (`tests/test_interop.py`, restrição 3 do enunciado) usa bibliotecas consolidadas apenas para conferir a saída do grupo. Ele é pulado automaticamente se elas não estiverem instaladas:

```bash
pip install -r requirements-dev.txt   # cryptography + pycryptodome
```

Esse teste verifica, nos dois sentidos, a compatibilidade do nosso OAEP com o PyCryptodome e do nosso PSS com o `cryptography` (OpenSSL) e com o PyCryptodome, todos com SHA3-256. O `cryptography` não é usado no OAEP porque o backend OpenSSL dele não aceita SHA3 nesse esquema.

| Arquivo de teste | Cobertura |
|---|---|
| `test_aritmetica.py` | exponenciação/inverso modular contra `pow`, I2OSP/OS2IP, XOR |
| `test_primos.py` | primos de Mersenne, números de Carmichael, pseudoprimos fortes, geração de primos |
| `test_chaves.py` | parâmetros (λ, CRT, \|p−q\|), exportação/importação, chaves corrompidas ou fracas |
| `test_oaep.py` | ida e volta, limite de 190 B, aleatoriedade, rótulo, cifrado adulterado, erro uniforme |
| `test_pss.py` | assinatura e verificação, salt, codificação EMSA, assinatura adulterada, "não é cifrar o hash" |
| `test_adulteracao.py` | **Parte IV**: (a) byte do arquivo, (b) byte da assinatura, (c) chave pública; estrutura malformada |
| `test_interop.py` | compatibilidade com bibliotecas consolidadas |
| `test_cli.py` | fluxo completo pela CLI e códigos de saída |

## Decisões de implementação

- **Aleatoriedade:** módulo `secrets` (CSPRNG do sistema operacional).
- **Primos:** os 2 bits mais altos são fixados (garante `p ≥ √2·2^(b−1)` e `n` com exatamente 2048 bits). Os candidatos passam por divisão por primos menores que 2000 e depois por Miller-Rabin com 40 rodadas de bases aleatórias. Exige-se também `mdc(p−1, e) = 1` e `|p − q| > 2^(1024−100)` (FIPS 186-5).
- **Chaves:** `e = 65537`; `d = e⁻¹ mod mmc(p−1, q−1)` com `d > 2^1024`; parâmetros do CRT pré-calculados.
- **Aritmética:** exponenciação por quadrados sucessivos e inverso via Euclides estendido, ambos implementados pelo grupo (não usamos `pow` do Python nas operações criptográficas).
- **Operação privada:** CRT, *blinding* aleatório (contra ataques de temporização) e verificação `y^e ≡ x` (contra ataques de falha).
- **OAEP:** decifragem sem desvios dependentes dos dados e com uma única mensagem de erro, para não criar oráculo de padding.
- **PSS:** `sLen = 32`, `emBits = modBits − 1`, verificação estrita de todos os campos da codificação.
- **Estrutura `.sig`:** os metadados servem só para diagnóstico. A validade depende apenas do PSS sobre o digest **recalculado** do arquivo.
- **Tratamento de erros:** toda falha previsível gera uma subclasse de `ErroRSA`. A CLI não exibe *stack traces* e `repr()` de uma chave privada não mostra os segredos.

Veja `docs/formatos.md` para os formatos e `docs/analise_seguranca.md` para a Parte V.

## Mapa enunciado → código

| Requisito | Onde |
|---|---|
| Miller-Rabin, primos p e q | `primos.nucleo_miller_rabin`, `primos.gerar_primo` |
| Chaves ≥ 2048 bits, parâmetros | `chaves.gerar_par_chaves`, `ChavePrivada.validar` |
| Importação/exportação documentada | `chaves.exportar_*` / `importar_*`, `docs/formatos.md` |
| OAEP + MGF1 com SHA3-256 | `oaep.codificar_oaep` / `decodificar_oaep`, `hashing.mgf1` |
| Detecção de padding/cifrado alterado | `oaep.decifrar` → `ErroDecifragem` |
| Digest SHA3-256 do arquivo | `hashing.sha3_256_arquivo` |
| PSS com MGF1 e salt | `pss.codificar_pss` / `verificar_codificacao_pss` |
| Assinatura em Base64 | `AssinaturaArquivo.serializar` |
| Parsing e verificação | `assinatura_arquivo.analisar` / `verificar_arquivo` |
| Testes (a), (b), (c) | `tests/test_adulteracao.py`, `demo.py` (Parte IV) |
| Análise de segurança | `docs/analise_seguranca.md`, `demo.py` (Parte V) |

## Referências

NIST FIPS 202 (SHA-3) · NIST SP 800-56B Rev. 2 · NIST FIPS 186-5 · RFC 8017 (PKCS #1 v2.2) · RFC 8032 (EdDSA).
