# CIC0201 — Trabalho de Implementação 1
## Cifra de Vigenère: Implementação e Criptoanálise

**Daniel de Oliveira Morais** (242042396) · **Davi Bragança e Silva** (242001473) · **Roberto Ribeiro Correa de Oliveira Neto** (242009936)

Implementação em **Python 3.8+**, arquivo único, sem dependências externas.

```
vigenere.py        cifra, criptoanálise, CLI e testes — arquivo único (~190 linhas)
exemplos/          textos claros e criptogramas de demonstração
relatorio.pdf      relatório técnico
```

## Como executar

```bash
# Parte I — cifrar / decifrar
python3 vigenere.py cifrar   -c MINHACHAVE -t "mensagem em texto claro"
python3 vigenere.py cifrar   -c MINHACHAVE -a mensagem.txt -o criptograma.txt
python3 vigenere.py decifrar -c MINHACHAVE -a criptograma.txt

# Parte II — ataque de recuperação da chave
python3 vigenere.py atacar -a criptograma.txt                 # idioma detectado automaticamente
python3 vigenere.py atacar -i pt -a criptograma_pt.txt -o recuperado.txt
python3 vigenere.py atacar -i en -a criptograma_en.txt --tamanho 7   # forçar tamanho
python3 vigenere.py atacar -a cripto.txt --max 30

# Testes
python3 vigenere.py testar
```

O ataque imprime, nesta ordem: tabela de IC por tamanho (com o limiar de decisão),
votos do exame de Kasiski, os 3 melhores candidatos por posição da chave (χ²),
a chave recuperada e a validação do texto decifrado (IC e χ²).

## Demonstração rápida
```bash
python3 vigenere.py atacar -a exemplos/criptograma_pt.txt   # → LIBERDADE
python3 vigenere.py atacar -a exemplos/criptograma_en.txt   # → CRYPTO
```

## Alfabeto adotado
* Alfabeto de trabalho **A–Z** (26 letras); maiúsculas/minúsculas cifradas igualmente, **caixa preservada**.
* Acentos normalizados para a letra base antes de cifrar (á→a, ç→c…).
* Espaços, números e pontuação **não são cifrados** e passam intactos (a criptoanálise os ignora).
* A chave deve conter ao menos uma letra.

---

## Projeto 2 — Assinatura Digital com RSA-OAEP e RSA-PSS

Implementação, relatório e apresentação em [`projeto-2-rsa/`](projeto-2-rsa/).
