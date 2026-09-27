# Pendências para apresentação e entrega

Checklist baseado no enunciado e na revisão do projeto. Itens concluídos indicam
correções implementadas e verificadas, não uma certificação de segurança.

## 1. RSA-OAEP — correção da decifragem

- [x] Rejeitar bytes diferentes de zero no padding anterior ao delimitador `0x01`.
- [x] Rejeitar a ausência do delimitador, hash do label incorreto e primeiro byte inválido.
- [x] Rejeitar representantes de ciphertext `>= n` antes da operação RSA.
- [x] Calcular o tamanho em bytes a partir do módulo, arredondando para cima, na cifragem e decifragem.
- [x] Unificar mensagens de erro para ciphertext inválido.
- [x] Remover a afirmação incorreta de proteção contra temporização.
- [x] Adicionar testes de regressão, mensagem vazia, limites, label, adulteração e módulo de 2049 bits.
- [x] Atualizar README e análise com o comportamento corrigido.

## 2. Importação de chaves privadas

- [x] Validar `algorithm`, tamanho declarado e parâmetros públicos.
- [x] Validar `qinv`, limites dos parâmetros e consistência matemática completa.
- [x] Rejeitar entradas inválidas sem exceções aritméticas não controladas.
- [x] Testar adulterações em cada parâmetro e importação/exportação válida.

O importador verifica limites antes das operações aritméticas, relações RSA/CRT
e primalidade probabilística dos fatores com Miller-Rabin. Os testes cobrem
adulterações, entradas malformadas e uso de uma chave válida após importação.

## 3. Cobertura das Partes I e II

- [ ] Testar exponenciação modular, máximo divisor comum e inverso modular.
- [ ] Testar Miller-Rabin com primos, compostos e casos de borda.
- [ ] Testar parâmetros inválidos da geração e consistência das chaves geradas.
- [ ] Adicionar vetores conhecidos de MGF1.
- [x] Testar ida e volta OAEP, limites e blocos malformados.
- [ ] Opcional: ampliar interoperabilidade independente para OAEP.

## 4. Apresentação e arguição

- [ ] Preparar roteiro de geração, exportação e importação das chaves.
- [ ] Disponibilizar comando ou script simples para demonstrar cifragem/decifragem OAEP e rejeição de adulteração.
- [ ] Encadear assinatura válida e as três adulterações obrigatórias em uma demonstração reproduzível.
- [ ] Ensaiar explicações de Miller-Rabin, MGF1, salt, OAEP versus PSS e confiança na chave pública.
- [ ] Revisar comentários sobre CRT: parâmetros são armazenados, mas as operações atuais não usam essa otimização.

O PDF exige apresentação, demonstração e arguição individual; não exige slides
nem uma CLI específica. A CLI de assinatura e os testes de adulteração já existem.

## 5. Entrega no Moodle

- [x] Preencher os quatro integrantes e matrículas no README.
- [x] Incluir análise de RSA sem padding, OAEP/PSS e comparação com Ed25519.
- [ ] Revisar limitações documentadas após as próximas correções.
- [ ] Executar a suíte final e conferir as instruções em um ambiente limpo.
- [ ] Montar e conferir o pacote com código, testes, README e análise, sem caches, ambientes virtuais ou chaves privadas pessoais.
- [ ] Conferir prazo/horário e enviar na plataforma Moodle.
