# CIC0201 — Trabalho de Implementação 2
## Sistema de Assinatura Digital e Verificação Segura de Arquivos (RSA-OAEP e RSA-PSS sobre SHA3-256)

**Daniel de Oliveira Morais** (242042396) · **Davi Bragança e Silva** (242001473) · **Roberto Ribeiro Correa de Oliveira Neto** (242009936)

Implementação em **Python 3.8+**, arquivo único, sem dependências externas e sem OpenSSL. Da biblioteca padrão, usa `hashlib` para o SHA3-256 e `secrets` para os números aleatórios. Miller-Rabin, aritmética modular, MGF1, OAEP e PSS são implementações próprias.

```
rsa_assinatura.py       geração de chaves, OAEP, PSS, arquivo .sig, demonstração e CLI
relatorio.pdf           relatório técnico
apresentacao_rsa.pptx   slides da apresentação
```

## Como executar

```bash
# Demonstração completa (Partes I a V, com os testes de adulteração)
python3 rsa_assinatura.py demo

# Parte I — gerar chaves RSA-2048 (cria alice.pub e alice.priv)
python3 rsa_assinatura.py gerar-chaves --saida alice

# Parte II — cifrar / decifrar com RSA-OAEP (mensagens de até 190 bytes)
python3 rsa_assinatura.py cifrar   --chave alice.pub  --mensagem "segredo" --saida msg.enc
python3 rsa_assinatura.py decifrar --chave alice.priv --entrada msg.enc

# Partes III e IV — assinar / verificar arquivo com RSA-PSS
python3 rsa_assinatura.py assinar   --chave alice.priv --arquivo contrato.txt
python3 rsa_assinatura.py verificar --chave alice.pub  --arquivo contrato.txt --assinatura contrato.txt.sig
```

Códigos de saída: `0` = sucesso ou assinatura válida; `1` = assinatura inválida ou falha de decifragem; `2` = erro de entrada.

## Organização do código

O arquivo segue a ordem do enunciado, com uma seção numerada para cada etapa:

| Seção | Conteúdo | Parte |
|---|---|---|
| 1 | Aritmética modular: `mdc`, `euclides_estendido`, `inverso_modular`, `potencia_modular` | I |
| 2 | `teste_miller_rabin`, `gerar_primo` | I |
| 3 | `gerar_par_de_chaves`, exportação e importação das chaves | I |
| 4 | `sha3_256`, `mgf1` | II e III |
| 5 | `rsa_operacao_publica`, `rsa_operacao_privada` (CRT, blinding e verificação) | — |
| 6 | `oaep_cifrar`, `oaep_decifrar` | II |
| 7 | `pss_assinar`, `pss_verificar` | III |
| 8 | Arquivo `.sig`: `assinar_arquivo`, `ler_texto_assinatura`, `verificar_arquivo` | IV |
| 9 | `executar_demonstracao`: testes (a) arquivo, (b) assinatura e (c) chave pública; RSA sem padding | IV e V |
| 10 | Linha de comando | — |

## Decisões principais

- **Chaves:** módulo de 2048 bits e `e = 65537`. Calcula-se `d = e⁻¹ mod mmc(p−1, q−1)` e aplicam-se as condições do FIPS 186-5, como `|p − q| > 2^924` e `d > 2^1024`.
- **Miller-Rabin:** 40 rodadas com bases aleatórias, antecedidas de divisão por primos menores que 2000.
- **Operação privada:** usa CRT, *blinding* contra ataques de tempo e verificação do resultado contra ataques de falha.
- **OAEP:** qualquer falha na decifragem gera o mesmo erro, `falha na decifragem`, para não criar um oráculo de padding.
- **PSS:** salt de 32 bytes. A assinatura é o bloco EMSA-PSS elevado a `d`, e não o hash cifrado.
- **Arquivo `.sig`:** a validade depende só da verificação PSS sobre o hash **recalculado** do arquivo. O cabeçalho serve apenas para explicar por que a verificação falhou.
