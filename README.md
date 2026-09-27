# Sistema de assinatura digital e verificação de arquivos

CIC0201 — Segurança Computacional, Trabalho 2, 2026/2.

| Integrante | Matrícula |
| --- | --- |
| Rafael de Lima Pereira | 242043277 |
| Pedro Freitas França | 232006028 |
| Rian Kallebe da Silva Lisboa | 242012000 |
| Arthur Martins Pereira de Souza | 241004499 |

Implementação didática em Python de RSA, OAEP e PSS com SHA3-256.
RSA, Miller-Rabin, MGF1 e paddings são implementados manualmente.
A execução principal usa apenas a biblioteca padrão; Python 3.9 ou superior.

## Organização

| Arquivo | Responsabilidade |
| --- | --- |
| `rsa_keygen.py` | Parte I: geração, aritmética e importação/exportação das chaves |
| `rsa_crypto.py` | Partes II–IV: OAEP, assinatura e verificação PSS |
| `signed_file.py` | Parte IV: estrutura assinada, parsing e interface de execução |
| `tests/test_verification.py` | Casos válidos, adulterações e entradas malformadas |
| `tests/test_oaep.py` | Cifragem/decifragem, limites e rejeição de padding inválido |
| `PENDENCIAS.md` | Checklist de correções, apresentação e entrega |
| `tests/test_interop.py` | Teste adicional opcional com biblioteca independente |
| `ANALISE_SEGURANCA.md` | Parte V: justificativas, comparação e limitações |

## Demonstração

Execute na raiz do projeto. A geração usa aleatoriedade e pode levar alguns segundos.
Os caminhos de saída são sobrescritos: use uma pasta de demonstração.

```sh
mkdir -p demo
python3 signed_file.py keygen demo/publica.json demo/privada.json
python3 signed_file.py sign README.md demo/privada.json demo/assinado.json
python3 signed_file.py verify demo/assinado.json demo/publica.json
```

Resultado esperado: `Arquivo íntegro: assinatura RSA-PSS válida para a chave pública fornecida.`
A assinatura é sobre os bytes incorporados ao JSON, não sobre o arquivo original que possa ter sido alterado posteriormente no disco.

Para demonstrar a troca de chave:

```sh
python3 signed_file.py keygen demo/outra-publica.json demo/outra-privada.json
python3 signed_file.py verify demo/assinado.json demo/outra-publica.json
```

Resultado esperado: `Assinatura inválida: arquivo, estrutura ou chave não correspondem.`
Códigos de saída: **0** sucesso; **1** assinatura/estrutura inválida; **2** falha de leitura, chave inválida ou erro de operação.

## Testes

```sh
python3 -m unittest discover -s tests -v
```

A suíte cobre arquivo válido, vazio e binário; alteração de um byte do conteúdo,
da assinatura e do módulo público; outra chave válida; JSON inválido/duplicado;
Base64 inválido; tamanhos e parâmetros inconsistentes; assinatura fora do intervalo;
padding PSS adulterado; salt probabilístico e códigos de saída da interface.
Os testes OAEP cobrem mensagem vazia e no limite, label incorreto, ciphertext
adulterado ou fora do intervalo, padding malformado e módulo de 2049 bits.
As chaves de teste são geradas pelo próprio projeto e não são gravadas no repositório.

O teste independente é opcional e fica marcado como `skipped` sem a dependência:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install cryptography
.venv/bin/python -m unittest discover -s tests -v
```

A biblioteca externa apenas verifica uma assinatura produzida pelo grupo, incluindo
um controle negativo. Não participa da implementação nem da geração das chaves.

## Formatos e contrato de verificação

As chaves são objetos JSON com `format`, `algorithm: "RSA"`, `key_size_bits`,
`created_at` e parâmetros inteiros representados em bytes big-endian/Base64.
A pública usa `CIC0201-RSA-PUB-v1` e os campos `n`, `e`.
A privada usa `CIC0201-RSA-PRIV-v1` e também `d`, `p`, `q`, `dp`, `dq`, `qinv`.
O timestamp é informativo, não autenticado. A chave privada fica em texto claro.

A estrutura assinada é um objeto JSON UTF-8 com exatamente estes campos:

```json
{
  "format": "CIC0201-SIGNED-v1",
  "algorithm": "RSA-PSS",
  "hash": "SHA3-256",
  "mgf": "MGF1-SHA3-256",
  "salt_length": 32,
  "content_b64": "<bytes originais em Base64>",
  "signature_b64": "<assinatura em Base64>"
}
```

O exemplo acima descreve o formato; os textos entre `<...>` são placeholders.
A assinatura autentica os bytes decodificados de `content_b64`. Os metadados são
fixos e validados estritamente; não há seleção de algoritmo controlada pelo arquivo.
Espaços e ordem dos campos JSON não alteram o conteúdo assinado. Campos duplicados,
extras, ausentes e Base64 não canônico são rejeitados. Arquivos vazios são válidos.
A chave pública é fornecida separadamente e deve vir de uma fonte confiável.

## Entrega no Moodle

Incluir os três módulos Python, a pasta `tests`, este README e a análise de segurança.
Executar os testes e conferir o conteúdo do pacote.
Não incluir `.venv`, caches ou chaves privadas pessoais. Os comandos acima geram
os exemplos necessários à apresentação. Consultar a [análise de segurança](ANALISE_SEGURANCA.md)
para a arguição e as limitações conhecidas.
