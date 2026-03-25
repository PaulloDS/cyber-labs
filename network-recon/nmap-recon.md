# Reconhecimento

## 🎯 Objetivo
Identificar hosts ativos e serviços expostos na rede interna.

## 🔧 Ferramenta
Nmap

## 🔍 Execução

```bash
sudo nmap -sn 192.168.56.0/24

📊 Resultado

Hosts identificados:

192.168.56.50 (Ubuntu Server)

192.168.56.30 (Windows)
```
## 🔎 Scan detalhado

```
sudo nmap -sS -sV 192.168.56.50

📊 Portas encontradas

22/tcp → SSH

80/tcp → HTTP

8080/tcp → Aplicação Web (DVWA)
```
