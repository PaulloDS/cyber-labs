# 🔐 NetGuard — Network Security Audit Toolkit

> Toolkit modular em Python para auditoria de segurança de redes e infraestrutura.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python)
![License](https://img.shields.io/badge/License-MIT-green)
![Status](https://img.shields.io/badge/Status-Em%20Desenvolvimento-yellow)

---

## 📌 Sobre o Projeto

O **NetGuard** é um toolkit de auditoria de segurança desenvolvido para auxiliar analistas e administradores de redes a identificar vulnerabilidades e configurações incorretas em sua infraestrutura.

O projeto foi construído com foco em aprendizado prático dos seguintes temas:

- Varredura e análise de portas TCP
- Verificação de headers de segurança HTTP
- Descoberta e inventário de hosts em redes locais
- Análise de logs em busca de padrões maliciosos
- Geração de relatórios de auditoria em HTML

> ⚠️ **Aviso Legal:** Este toolkit foi desenvolvido para fins educacionais e para uso em ambientes autorizados. O uso em sistemas sem autorização explícita é ilegal. Sempre obtenha permissão antes de executar qualquer varredura.

---

## 🧩 Módulos

| Módulo | Descrição | Comando |
|--------|-----------|---------|
| 🔍 Port Scanner | Varre portas TCP e identifica serviços de risco | `port-scan` |
| 🌐 Header Checker | Verifica headers de segurança HTTP | `header-check` |
| 🗺 Network Inventory | Mapeia hosts ativos na rede local | `inventory` |
| 📋 Log Analyzer | Detecta brute force e padrões suspeitos em logs | `log-analyze` |
| 📊 Report Generator | Gera relatório HTML consolidado | (usado pelo `full-audit`) |

---

## 🚀 Como Usar

### Pré-requisitos

- Python 3.9 ou superior
- Nenhuma dependência externa necessária (apenas biblioteca padrão)

### Instalação

```bash
git clone https://github.com/seuperfil/netguard.git
cd netguard
```

### Exemplos de Uso

#### Port Scan
```bash
# Varrer portas 1-1024 de um host
python main.py port-scan 192.168.1.1

# Varrer portas específicas
python main.py port-scan 192.168.1.1 --ports 22,80,443,3389,3306
```

#### Verificação de Headers HTTP
```bash
python main.py header-check https://exemplo.com
```

#### Inventário de Rede
```bash
# Requer privilégios de administrador/root para ping
python main.py inventory 192.168.1.0/24
```

#### Análise de Log
```bash
# Log de autenticação SSH (Linux)
python main.py log-analyze /var/log/auth.log --type auth

# Usando o log de exemplo incluso
python main.py log-analyze logs/sample_auth.log --type auth

# Log do Apache
python main.py log-analyze /var/log/apache2/access.log --type apache
```

#### Auditoria Completa com Relatório HTML
```bash
python main.py full-audit 192.168.1.1 \
  --network 192.168.1.0/24 \
  --logfile logs/sample_auth.log \
  --output reports/meu_relatorio.html
```

---

## 📊 Exemplo de Output

### Terminal
```
  PORTA    SERVIÇO        SEVERIDADE  OBSERVAÇÃO
  ──────────────────────────────────────────────
  21       FTP            HIGH        Transferência de arquivos sem criptografia
  22       SSH            LOW         Acesso remoto seguro — verificar versão
  23       Telnet         HIGH        Protocolo legado sem criptografia
  80       HTTP           MEDIUM      Tráfego não criptografado
  443      HTTPS          LOW         Verificar certificado e versão TLS
  3306     MySQL          HIGH        Banco de dados exposto publicamente
```

### Relatório HTML
O comando `full-audit` gera um relatório completo em HTML com:
- Resumo executivo com contagem de severidades
- Tabelas detalhadas por módulo
- Código de cores por severidade (Alta / Média / Baixa)
- Seção de IPs com brute force detectado

---

## 🗂 Estrutura do Projeto

```
netguard/
├── main.py                    # Ponto de entrada principal
├── requirements.txt           # Dependências (stdlib only)
├── modules/
│   ├── port_scanner.py        # Módulo 1: Varredura de portas
│   ├── header_checker.py      # Módulo 2: Headers HTTP
│   ├── network_inventory.py   # Módulo 3: Inventário de rede
│   ├── log_analyzer.py        # Módulo 4: Análise de logs
│   └── report_generator.py    # Módulo 5: Relatório HTML
├── logs/
│   └── sample_auth.log        # Log de exemplo para testes
└── reports/                   # Relatórios gerados (gitignored)
```

---

## 🧠 O que Aprendi Construindo Esse Projeto

- **Sockets TCP** e como funcionam conexões de rede em baixo nível
- **Threading** para varredura paralela de portas com segurança de concorrência
- **Headers HTTP de segurança** e seu papel na proteção de aplicações web
- **Protocolos de rede** como ARP, ICMP e como mapear dispositivos
- **Regex** para análise de padrões em logs de sistema
- **Estrutura de projetos Python** com módulos separados por responsabilidade

---

## 🛣 Roadmap

- [ ] Adicionar suporte a IPv6
- [ ] Integrar com API do VirusTotal para verificar IPs suspeitos
- [ ] Módulo de análise de certificado SSL/TLS
- [ ] Exportação de relatório em PDF
- [ ] Interface de linha de comando com `rich` para output mais visual
- [ ] Integração com Shodan API

---

## 📚 Referências e Recursos

- [OWASP Secure Headers Project](https://owasp.org/www-project-secure-headers/)
- [Cisco Networking Academy](https://www.netacad.com/)
- [TryHackMe](https://tryhackme.com/)
- [Python `socket` documentation](https://docs.python.org/3/library/socket.html)

---

## 👨‍💻 Autor

**Seu Nome** — Formando em Engenharia de Software | Estudante de Cibersegurança

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?logo=linkedin)](https://linkedin.com/in/seuperfil)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-black?logo=github)](https://github.com/seuperfil)

---

## 📄 Licença

Distribuído sob a licença MIT. Veja `LICENSE` para mais informações.
