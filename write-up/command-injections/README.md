# 🐚 HTB Academy — Command Injections | Skills Assessment

![HTB](https://img.shields.io/badge/Hack%20The%20Box-Academy-9FEF00?style=for-the-badge&logo=hackthebox&logoColor=white)
![Module](https://img.shields.io/badge/M%C3%B3dulo-Command%20Injections-blue?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Conclu%C3%ADdo-success?style=for-the-badge)
![Cert](https://img.shields.io/badge/Trilha-CPTS-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-Educational-lightgrey?style=for-the-badge)

> Write-up autoral do Skills Assessment final do módulo **Command Injections** da HTB Academy, parte da minha preparação para a certificação **CPTS (Certified Penetration Testing Specialist)**.

---

## 📑 Sumário

- [Introdução](#-introdução)
- [Visão Geral do Alvo](#-visão-geral-do-alvo)
- [Enumeração Inicial](#-enumeração-inicial)
- [Testando Cada Ação do File Manager](#-testando-cada-ação-do-file-manager)
- [Identificando a Vulnerabilidade](#-identificando-a-vulnerabilidade)
- [Enumerando os Filtros](#-enumerando-os-filtros)
- [Ofuscação de Comando](#-ofuscação-de-comando)
- [Exploração](#-exploração)
- [Metodologia Aplicada](#-metodologia-aplicada)
- [Lições Aprendidas](#-lições-aprendidas)
- [Skills Desenvolvidas](#-skills-desenvolvidas)
- [Conclusão](#-conclusão)

---

## 🎯 Introdução

O Skills Assessment final do módulo **Command Injections** apresenta um cenário realista: um **gerenciador de arquivos web**. À primeira vista, a aplicação parece simples, mas como em muitos file managers reais, operações de backend costumam depender de comandos do sistema operacional, o que os torna alvos atrativos para testes de **OS Command Injection**.

Diferente dos labs anteriores do módulo, esse assessment **não expõe um parâmetro obviamente vulnerável**. O desafio real está em:

1. Identificar qual funcionalidade efetivamente invoca um comando de sistema;
2. Contornar múltiplos filtros de entrada para alcançar execução arbitrária de comandos.

Este write-up documenta todo o meu raciocínio, incluindo tentativas sem sucesso, o porquê de cada decisão e a exploração final.

> <img src="https://i.imgur.com/EixDQrt.png"/>

---

## 🗂️ Visão Geral do Alvo

Após autenticação, o gerenciador de arquivos expunha as seguintes funcionalidades:

| Funcionalidade | Descrição |
|---|---|
| 🔍 Search | Busca de arquivos por nome |
| 👁️ Preview | Visualização de conteúdo |
| 📋 Copy | Cópia de arquivos |
| 📦 Move | Movimentação de arquivos |
| 🔗 Direct Link | Geração de link direto |
| ⬇️ Download | Download de arquivo |

Como o módulo tratava exclusivamente de OS Command Injection, a hipótese inicial era que uma (ou mais) dessas features executasse comandos do sistema operacional no backend.

**Objetivo:**
> Identificar uma vulnerabilidade de command injection e recuperar o conteúdo de `/flag.txt`.

---

## 🔬 Enumeração Inicial

### Testando o Campo de Busca

O vetor de ataque mais óbvio era a caixa de pesquisa. Testei os payloads clássicos abordados ao longo do módulo:

```bash
;
&&
||
|
%0a
$()
```

Também explorei diversas técnicas de bypass:

- URL encoding
- Tabs (`%09`)
- `${IFS}`
- Variáveis de ambiente
- Substituição de caracteres
- Ofuscação de comandos

**Resultado:** nenhum payload produziu comportamento interessante. Sem execução de comando, sem erros, sem indícios de que a entrada do usuário chegasse a um shell.

> <img src="https://i.imgur.com/Z881jkk.png"/>

**Conclusão parcial:** a funcionalidade de busca provavelmente não era vulnerável.

---

## 🧪 Testando Cada Ação do File Manager

Com a busca descartada, passei a avaliar individualmente cada ação disponível por arquivo.

### 👁️ Preview

Todo arquivo simplesmente exibia seu conteúdo. Um dos arquivos continha inclusive a seguinte mensagem:

> *"Stop looking at these random documents! Don't you have some injection to do :)"*

Isso reforçou fortemente que o Preview não era a funcionalidade-alvo pretendida.

---

### 📋 Copy

Próximo candidato: a operação **Copy**. Interceptei a requisição com o Burp Suite e tentei injetar comandos através do parâmetro `from`.

**Payload:**
```http
GET /index.php?to=&from=;%09whoami&finish=1
```

**Resposta:**
```html
Error while copying from <b>; whoami</b> to <b>; whoami</b>
```

Observação importante: em vez de executar meu payload, a aplicação simplesmente o **ecoou de volta** na interface. O payload nunca pareceu alcançar o shell.

> <img src="https://i.imgur.com/irkBxHL.png"/>

Após tentativas adicionais, concluí que Copy não era o ponto de injeção.

---

### 📦 Move

Segui inicialmente a mesma estratégia usada em Copy:

```
nome_original_do_arquivo;payload
```

Novamente, nada aconteceu.

Nesse momento, mudei completamente a abordagem: em vez de anexar o payload a um nome de arquivo existente, **removi o nome do arquivo por completo** e testei apenas o operador de injeção.

**Payload:**
```text
;%09
```

Essa pequena mudança alterou completamente o comportamento da aplicação.

---

## 🚨 Identificando a Vulnerabilidade

A resposta deixou de ser um erro de validação de frontend. Em vez disso, recebi um **erro de backend**:

```text
Error while moving:

mv: missing destination file operand after '/var/www/html/files/'
Try 'mv --help' for more information.

bash: /var/www/html/files/: Is a directory
```

Esse foi o ponto de virada. Ficou imediatamente claro que:

- ✅ O backend executava o comando Linux `mv`;
- ✅ A entrada controlada pelo usuário chegava ao shell;
- ✅ Command injection era possível.

A partir daqui, o desafio deixou de ser **encontrar** a vulnerabilidade e passou a ser **contornar seus filtros**.

> <img src="https://i.imgur.com/h3RA8VH.png"/>

---

## 🛡️ Enumerando os Filtros

Com o ponto de injeção confirmado, iniciei os testes de filtro. Diversas técnicas comuns se mostraram bloqueadas, entre elas:

- Comandos codificados em Base64
- Separadores padrão
- Truques com variáveis de ambiente
- Diversos bypasses estudados ao longo do módulo

A maioria das tentativas falhou. No entanto, **reverter comandos e reconstruí-los dinamicamente** se mostrou muito mais eficaz.

Antes de tentar ler a flag, confirmei a execução de comandos com algo inofensivo:

```bash
ls -la
```

Com a execução confirmada, foquei em contornar a blacklist de comandos.

---

## 🎭 Ofuscação de Comando

A execução direta de:

```bash
cat /flag.txt
```

estava sendo filtrada. Para contornar a blacklist, combinei múltiplas técnicas aprendidas no módulo:

- Manipulação de maiúsculas/minúsculas
- `tr` para converter caracteres para minúsculo
- Manipulações para gerar o caractere `/` sem digitá-lo diretamente
- Tab (`%09`) no lugar de espaços
- Obtive o payload final e consegui capturar a flag

Embora o payload nunca contivesse explicitamente a string `cat /flag.txt`, o shell a reconstruía durante a execução driblando o filtro de comandos.

---

## 💥 Exploração

O backend executou o payload com sucesso. Após validar a execução com `ls -la`, adaptei o payload para ler:

```text
/flag.txt
```

A aplicação retornou o conteúdo do arquivo, concluindo o assessment.

> <img src="https://i.imgur.com/1ydW1c9.png"/>

---

## 🔁 Metodologia Aplicada

```
┌─────────────────────┐
│  Enumeração inicial  │  → Testar campo de busca (payloads clássicos)
└──────────┬───────────┘
           ▼
┌─────────────────────┐
│ Testar cada feature  │  → Preview, Copy, Move (individualmente)
└──────────┬───────────┘
           ▼
┌─────────────────────┐
│ Alterar estratégia   │  → Remover filename, testar só o operador
└──────────┬───────────┘
           ▼
┌─────────────────────┐
│ Ler erro de backend  │  → Confirma comando `mv` e injeção viável
└──────────┬───────────┘
           ▼
┌─────────────────────┐
│ Confirmar execução   │  → Payload inofensivo (ls -la)
└──────────┬───────────┘
           ▼
┌─────────────────────┐
│ Enumerar filtros     │  → Identificar o que é bloqueado
└──────────┬───────────┘
           ▼
┌─────────────────────┐
│ Ofuscar payload      │  → tr + ofuscação de comandos + %09
└──────────┬───────────┘
           ▼
┌─────────────────────┐
│  Exploração final    │  → Leitura de /flag.txt
└─────────────────────┘
```

---

## 📚 Lições Aprendidas

- 🔸 Nunca assumir que o campo de entrada mais óbvio é o vulnerável.
- 🔸 Mensagens de erro de backend frequentemente revelam exatamente qual comando de sistema está sendo executado.
- 🔸 Confirmar a execução de comando antes de investir tempo em bypasses complexos.
- 🔸 Pequenas mudanças na estrutura do payload podem alterar completamente como o backend processa a entrada.
- 🔸 Técnicas de ofuscação de comando são extremamente valiosas quando payloads simples são bloqueados.

O maior aprendizado deste lab foi que **metodologia importa mais do que decorar payloads**. Encontrar a funcionalidade vulnerável exigiu paciência, observação e testes sistemáticos, só depois de identificado o ponto de injeção as técnicas do módulo se combinaram naturalmente para gerar execução de comando bem-sucedida.

---

## 🧠 Skills Desenvolvidas

- OS Command Injection (blind e com retorno de erro)
- Análise de mensagens de erro de backend para fingerprint de comandos
- Bypass de blacklists de comandos via ofuscação e reconstrução dinâmica de strings
- Interceptação e manipulação de requisições com Burp Suite
- Metodologia sistemática de enumeração de superfície de ataque

---

## ✅ Conclusão

Este foi um dos labs mais interessantes do módulo Command Injections, pois exigiu muito mais do que simplesmente tentar payloads conhecidos. O verdadeiro desafio foi identificar **onde** a aplicação de fato executava comandos do sistema operacional. Somente após confirmar a funcionalidade vulnerável foi possível aplicar as técnicas de bypass de filtro aprendidas ao longo do módulo.

Combinando enumeração cuidadosa, análise de erros de backend e técnicas de ofuscação de comando, foi possível alcançar execução arbitrária de comandos e recuperar o conteúdo de `/flag.txt`.

Esse assessment reforça um princípio central em pentest: **entender o comportamento da aplicação vale mais do que ter uma grande coleção de payloads**.

---

<div align="center">

📌 Parte da minha trilha de estudos rumo à certificação **HTB CPTS**.
Confira outros write-ups no meu perfil.

</div>
