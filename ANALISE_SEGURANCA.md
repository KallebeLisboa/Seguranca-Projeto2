# Parte V — Análise de segurança

## RSA sem padding, OAEP e PSS

RSA bruto é determinístico: cifrar a mesma mensagem com a mesma chave produz o
mesmo resultado. Sua estrutura multiplicativa permite manipular representantes
algébricos. Aplicar a exponenciação privada diretamente a um hash também não
constitui o esquema RSA-PSS exigido.

OAEP é um esquema de **cifragem**: combina hash, MGF1 e semente aleatória antes
da operação pública. A operação privada recupera o bloco e valida sua estrutura.
Seu objetivo é confidencialidade; qualquer pessoa com a chave pública pode cifrar,
portanto isso não comprova quem enviou a mensagem.

PSS é um esquema de **assinatura**: combina o hash da mensagem com salt, MGF1 e
uma codificação estruturada antes da operação privada. A chave pública verifica
a assinatura. Salt aleatório permite assinaturas diferentes da mesma mensagem.
O objetivo é integridade e autenticidade relativas à chave, sem ocultar o arquivo.
Essas construções e suas condições de segurança estão descritas na
[RFC 8017, seções 7.1, 8.1 e 9.1](https://www.rfc-editor.org/rfc/rfc8017).

## Parâmetros e verificação nesta implementação

SHA3-256 produz um digest de 32 bytes. É uma função da família padronizada em
[FIPS 202](https://csrc.nist.gov/pubs/fips/202/final). O trabalho usa SHA3-256
tanto para o digest quanto em MGF1, com salt PSS de 32 bytes. Isso define o perfil
do projeto; não se deve presumir compatibilidade com configurações padrão de
outras ferramentas.

O verificador calcula `emBits = bit_length(n) - 1`, verifica o tamanho da assinatura
e rejeita o representante `s >= n` antes da exponenciação. Confere o trailer
`0xbc`, os bits superiores, os zeros de padding, o delimitador e o hash reconstruído
com o salt recuperado. O hash final é comparado com `hmac.compare_digest`.
Isso evita aceitar apenas um hash coincidente sem validar a codificação PSS.

O parser rejeita campos repetidos, perfis desconhecidos e Base64 inválido ou não
canônico. Essa decisão elimina interpretações ambíguas entre produtor e consumidor.
A verificação da chave confere tamanho declarado, módulo ímpar de pelo menos
2048 bits e expoente público ímpar no intervalo permitido. Essas verificações
estruturais não provam que o módulo foi gerado corretamente nem certificam seu dono.

Alterar um byte do conteúdo muda a mensagem verificada; alterar a assinatura muda
o representante RSA; alterar o módulo ou trocar a chave muda a operação pública.
Os testes exercitam cada caso separadamente e exigem rejeição. Também preservam
um caso válido, evitando que um verificador que rejeite tudo passe na suíte.

## Comparação com Ed25519

| Aspecto | RSA-PSS deste projeto | Ed25519 |
| --- | --- | --- |
| Base matemática | Problema RSA, relacionado à fatoração de inteiros | Logaritmo discreto em curva de Edwards |
| Assinatura | 256 bytes com módulo de 2048 bits | 64 bytes |
| Chave pública | Módulo de 256 bytes mais expoente e formato | 32 bytes na codificação padrão |
| Hash | SHA3-256 neste perfil | SHA-512 no Ed25519 puro |
| Aleatoriedade na assinatura | Salt aleatório de 32 bytes | Nonce derivado deterministicamente da chave e mensagem |
| Configuração | Módulo, hash, MGF e salt | Perfil mais fixo e compacto |

Ed25519 reduz armazenamento e tráfego de chaves/assinaturas e dispensa uma nova
fonte de aleatoriedade a cada assinatura, mas a geração da chave ainda precisa de
aleatoriedade segura. Desempenho depende da implementação; este trabalho não
apresenta benchmark. Ed25519 é assinatura, não substituto de OAEP para cifragem.
A especificação é a [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032).
Tamanho de chave não equivale diretamente a força de segurança entre famílias;
um módulo RSA de 2048 bits não significa 2048 bits de segurança.

## Limitações e confiança

A chave pública deve ser autenticada por um canal independente. Se um atacante
substituir conteúdo, assinatura e chave por um conjunto próprio consistente, a
verificação matemática terá sucesso. Ela não determina identidade por si só,
nem prova horário de assinatura. Também não detecta reenvio de um pacote antigo.

A implementação é didática: exponenciação manual e inteiros Python não oferecem
garantia de tempo constante; não há blinding RSA. `compare_digest` melhora uma
comparação específica e não torna todo o programa resistente a canais laterais.
As chaves privadas são JSON sem cifragem. O parser carrega todo o arquivo na memória
e não impõe quotas para entradas gigantes, portanto não deve ser exposto como
serviço de verificação de conteúdo não confiável sem limites adicionais.

A decifragem OAEP valida o primeiro byte, o hash do label, todos os zeros do
padding e o delimitador. Rejeita representantes de ciphertext maiores ou iguais
a `n` antes da exponenciação. Falhas de ciphertext usam a mesma mensagem de erro;
o hash do label é comparado com `compare_digest`. A varredura percorre todo o
bloco recuperado, mas os desvios condicionais e a aritmética Python continuam
sem garantia de tempo constante. Os testes incluem blocos OAEP malformados,
limites de mensagem e módulos não alinhados em bytes. A importação privada valida algoritmo, tamanho e parâmetros públicos, limites
dos fatores e expoentes, produto dos fatores e relações RSA/CRT, incluindo
`qinv`. Também reaplica Miller-Rabin aos fatores (20 rodadas por fator); essa
verificação é probabilística, não uma prova de primalidade. O formato próprio
exige `d` como inverso canônico módulo `phi(n)`, conforme a geração do projeto.
Isso não é um importador genérico de outros formatos RSA. As demais pendências
estão em [PENDENCIAS.md](PENDENCIAS.md).

O teste de interoperabilidade adicional verifica a saída PSS manual com uma
implementação independente e rejeita uma mensagem alterada. Isso dá evidência de
compatibilidade do perfil testado, sem constituir prova formal de segurança ou
auditoria de todos os caminhos do programa.
