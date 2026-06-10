# Methodology Used

Durante a execução deste laboratório, foi utilizada uma abordagem incremental baseada na expansão da superfície de ataque descoberta.

## Phase 1 – Initial Enumeration

O alvo inicial retornava apenas respostas `403 Forbidden`, indicando que recursos potencialmente interessantes estavam ocultos.

Foi realizada enumeração de conteúdo utilizando wordlists da SecLists para identificar diretórios acessíveis.

Técnicas utilizadas:

* Directory Fuzzing
* Recursive Enumeration
* Response Analysis

---

## Phase 2 – Hidden Endpoint Discovery

Após encontrar o diretório `/admin`, foi realizada enumeração adicional com extensões específicas.

A enumeração padrão identificou apenas:

```text
/admin/index.php
```

Porém, a enumeração utilizando extensões revelou:

```text
/admin/panel.php
```

Esta etapa demonstrou a importância de não depender exclusivamente de wordlists e configurações padrão.

Técnicas utilizadas:

* Extension Fuzzing
* Content Discovery

---

## Phase 3 – Parameter Enumeration

O endpoint identificado retornava uma mensagem indicando a existência de um parâmetro obrigatório:

```text
Invalid parameter, please ensure accessID is set correctly
```

A partir dessa informação foi iniciado o processo de fuzzing de valores para o parâmetro descoberto.

Técnicas utilizadas:

* Manual Validation
* Parameter Value Fuzzing
* Response Filtering

---

## Phase 4 – Virtual Host Enumeration

O valor correto do parâmetro revelou uma nova pista apontando para um Virtual Host específico.

Após a configuração do hostname local, foi realizada enumeração adicional de VHosts.

Essa etapa revelou um segundo hostname oculto, expandindo significativamente a superfície de ataque disponível.

Técnicas utilizadas:

* VHost Enumeration
* Host Header Manipulation

---

## Phase 5 – Deep Content Enumeration

O novo Virtual Host continha um diretório chamado `godeep`, que servia como ponto inicial para uma cadeia de enumeração sucessiva.

Cada diretório encontrado continha uma nova pista direcionando para o próximo nível da estrutura.

Técnicas utilizadas:

* Recursive Directory Fuzzing
* Manual Validation
* Guided Enumeration

---

## Phase 6 – Objective Completion

Após múltiplos níveis de enumeração, o recurso final contendo a flag foi localizado.

O desafio exigiu a combinação prática de todos os conceitos abordados ao longo do módulo, simulando um fluxo real de descoberta de recursos ocultos em aplicações web.


# Lessons Learned

## 1. Mensagens de erro são fontes valiosas de informação

A descoberta do parâmetro `accessID` não ocorreu através de brute force, mas sim pela análise cuidadosa da mensagem retornada pela aplicação.

Pequenos detalhes frequentemente revelam informações relevantes para os próximos passos de uma avaliação.

---

## 2. Nem sempre a enumeração padrão é suficiente

A enumeração inicial revelou apenas `index.php`.

O endpoint mais importante do laboratório (`panel.php`) foi descoberto somente após a utilização de fuzzing com extensões específicas.

Isso reforça a necessidade de adaptar a metodologia quando os resultados parecem insuficientes.

---

## 3. Filtros reduzem ruído e aumentam eficiência

O uso de filtros por quantidade de palavras permitiu eliminar milhares de respostas repetitivas e destacar rapidamente resultados relevantes.

Em ambientes reais, a correta utilização de filtros pode reduzir significativamente o tempo gasto em enumeração.

---

## 4. VHosts fazem parte da superfície de ataque

A descoberta do Virtual Host oculto foi um dos pontos centrais do laboratório.

Muitas aplicações hospedam funcionalidades administrativas, ambientes de teste ou sistemas legados em Virtual Hosts que não aparecem durante uma navegação convencional.

---

## 5. Seguir pistas pode ser tão importante quanto executar ferramentas

Diversos passos do desafio foram guiados por mensagens deixadas pela própria aplicação.

A interpretação correta dessas pistas foi tão importante quanto o uso das ferramentas de fuzzing.

---

## 6. Fuzzing é um processo iterativo

O laboratório demonstrou que fuzzing não consiste apenas em executar uma wordlist.

Cada resultado encontrado gerou uma nova hipótese, que levou a uma nova enumeração e consequentemente a uma nova descoberta.

O processo completo seguiu o ciclo:

```text
Discover → Analyze → Validate → Pivot → Repeat
```

Essa mentalidade é diretamente aplicável a atividades de Pentest, AppSec e Red Teaming.

---

## 7. O valor está no processo

A flag foi apenas o resultado final.

O principal aprendizado foi desenvolver um processo estruturado de enumeração, validação e expansão da superfície de ataque utilizando diferentes técnicas de Web Fuzzing.
