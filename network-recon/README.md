# Enterprise Web Application Compromise Lab

## 📌 Overview

Este projeto simula um cenário real de comprometimento de servidor em ambiente corporativo, partindo de uma aplicação web vulnerável até a obtenção de acesso remoto ao sistema.

O objetivo é demonstrar, de forma prática, o fluxo completo de um ataque:

- Reconhecimento
- Enumeração
- Exploração
- Execução remota de comandos (RCE)
- Pós-exploração

---

## 🧠 Cenário

Ambiente interno simulando uma rede corporativa:

- Servidor Linux (Ubuntu) com aplicação web vulnerável (DVWA)
- Máquina atacante (Kali Linux)
- Máquina cliente (Windows)

---

## 🎯 Objetivo

Obter acesso ao servidor através de exploração de vulnerabilidade web e realizar pós-exploração.

---

## 🛠️ Tecnologias e Ferramentas

- Kali Linux
- Ubuntu Server
- DVWA (Damn Vulnerable Web Application)
- Nmap
- Netcat
- Bash

---

## 🧱 Arquitetura
-- Kali Linux (Attacker) → 192.168.56.20
-- Ubuntu Server (Target) → 192.168.56.10
-- Windows Client → 192.168.56.30

---

## 🔗 Etapas do Ataque

1. Reconhecimento de rede
2. Identificação de serviço web
3. Acesso via credenciais padrão
4. Exploração de Command Injection
5. Execução remota de comandos
6. Obtenção de reverse shell
7. Pós-exploração

---

## 🚨 Impacto

Comprometimento total do servidor com execução remota de comandos.

---

## 🛡️ Recomendações

- Remoção de credenciais padrão
- Validação de inputs (evitar command injection)
- Implementação de WAF
- Monitoramento de logs

---
