# Guia rápido de execução

Use Python 3.9 ou superior. Abra o terminal na pasta do projeto.
Os comandos abaixo são para macOS/Linux. A execução principal não precisa instalar dependências.

## 1. Gerar chaves, assinar e verificar

```sh
mkdir -p demo
python3 signed_file.py keygen demo/publica.json demo/privada.json
python3 signed_file.py sign README.md demo/privada.json demo/assinado.json
python3 signed_file.py verify demo/assinado.json demo/publica.json
```

O resultado final deve ser `Arquivo íntegro: assinatura RSA-PSS válida para a chave pública fornecida.`
Para assinar outro arquivo, substitua `README.md` pelo caminho desejado.
O JSON incorpora o conteúdo assinado: a verificação confere esses bytes,
não uma versão posterior do arquivo original no disco. Os comandos sobrescrevem
os caminhos de saída; preserve as chaves necessárias para seus exemplos.

## 2. Demonstrar cifragem e decifragem OAEP

Depois de gerar as chaves no passo anterior:

```sh
python3 - <<'PY'
from rsa_keygen import import_public_key, import_private_key
from rsa_crypto import rsa_oaep_encrypt, rsa_oaep_decrypt

publica = import_public_key('demo/publica.json')
privada = import_private_key('demo/privada.json')
mensagem = b'Ola, RSA-OAEP!'
cifrado = rsa_oaep_encrypt(publica, mensagem)
print('Ciphertext (hex):', cifrado.hex())
print('Mensagem recuperada:', rsa_oaep_decrypt(privada, cifrado).decode())
PY
```

Com RSA de 2048 bits e SHA3-256, a mensagem pode ter até 190 bytes.

## 3. Executar testes e adulterações

```sh
python3 -m unittest discover -s tests -v
```

A suíte testa, entre outros casos, alteração do conteúdo, assinatura, chave e
ciphertext, além de entradas inválidas. O resultado esperado é `OK`; os dois
testes de interoperabilidade podem aparecer como `skipped` sem as dependências opcionais.

Para executar também as verificações com bibliotecas independentes:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install cryptography pycryptodome
.venv/bin/python -m unittest discover -s tests -v
```

## 4. Demonstrar uma verificação inválida

```sh
python3 signed_file.py keygen demo/outra-publica.json demo/outra-privada.json
python3 signed_file.py verify demo/assinado.json demo/outra-publica.json
```

Resultado esperado: `Assinatura inválida: arquivo, estrutura ou chave não correspondem.`
O comando retorna código 1 nesse caso. Código 0 indica sucesso; 2 indica erro
na leitura, chave inválida ou falha de operação.

Consulte o [README](README.md) para os formatos e a entrega, e a
[análise de segurança](ANALISE_SEGURANCA.md) para as justificativas e limitações.
