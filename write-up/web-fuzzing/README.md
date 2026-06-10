# HTB Academy - Web Fuzzing Skills Assessment Write-up

## Overview

Este laboratório teve como objetivo aplicar os principais conceitos abordados no módulo de Web Fuzzing:

* Directory Fuzzing
* Recursive Fuzzing
* Extension Fuzzing
* Parameter Discovery
* Parameter Value Fuzzing
* Response Filtering
* Virtual Host Enumeration
* Deep Content Enumeration

O desafio exigiu a combinação de diversas técnicas em sequência até a descoberta da flag final.

---

# 1. Reconhecimento Inicial

O alvo fornecido seguia o padrão:

```bash
http://IP:PORT
```

Ao acessar a página principal, o servidor retornava apenas:

```text
403 Forbidden
```

Portanto, iniciamos a enumeração de diretórios.

---

# 2. Directory Fuzzing

## FFUF

```bash
ffuf \
-u http://IP:PORT/FUZZ \
-w /usr/share/seclists/Discovery/Web-Content/common.txt
```

### Resultado

```text
admin [Status: 301]
```

Foi identificado o diretório:

```text
/admin
```

---

# 3. Recursive Fuzzing

Ao acessar `/admin`, foi realizado fuzzing recursivo.

```bash
ffuf \
-u http://IP:PORT/admin/FUZZ \
-w /usr/share/seclists/Discovery/Web-Content/common.txt
```

### Resultado

```text
index.php [Status: 200]
```

Ao acessar:

```bash
curl http://IP:PORT/admin/index.php
```

Resposta:

```text
Access Denied
```

Nenhuma informação adicional foi obtida.

---

# 4. Extension Fuzzing

Como o conteúdo encontrado não parecia ser o objetivo final, foi realizada enumeração utilizando extensões específicas.

```bash
ffuf \
-u http://IP:PORT/admin/FUZZ \
-w /usr/share/seclists/Discovery/Web-Content/common.txt \
-e .php,.html,.js
```

### Resultado

```text
panel.php [Status: 200]
```

---

# 5. Descoberta de Parâmetro

Ao acessar:

```bash
curl http://IP:PORT/admin/panel.php
```

Obtivemos:

```text
Invalid parameter, please ensure accessID is set correctly
```

A mensagem revelou a existência do parâmetro:

```text
accessID
```

---

# 6. Parameter Value Fuzzing

Primeiro verificamos a resposta padrão:

```bash
curl "http://IP:PORT/admin/panel.php?accessID=test"
```

Com base na resposta obtida, utilizamos filtros para remover os resultados repetitivos.

```bash
ffuf \
-u "http://IP:PORT/admin/panel.php?accessID=FUZZ" \
-w /usr/share/seclists/Discovery/Web-Content/common.txt \
-mc all \
-fw 8
```

### Resultados Encontrados

```text
Documents and Settings
Program Files
getaccess
report list
```

Entre os resultados, apenas:

```text
getaccess
```

retornava uma resposta diferenciada.

---

# 7. Validando o Resultado

```bash
curl "http://IP:PORT/admin/panel.php?accessID=getaccess"
```

Resposta:

```text
Head on over to the fuzzing_fun.htb vhost for some more fuzzing fun!
```

Isso indicava claramente a existência de um Virtual Host.

---

# 8. Configurando o Virtual Host

Adicionamos o hostname ao arquivo hosts.

```bash
echo "IP fuzzing_fun.htb" | sudo tee -a /etc/hosts
```

Acessando:

```bash
http://fuzzing_fun.htb:PORT
```

Recebemos:

```text
Welcome to fuzzing_fun.htb!

Your next starting point is in the godeep folder - but it might be on this vhost, it might not, who knows...
```

A dica sugeria:

* Um diretório chamado `godeep`
* Possivelmente localizado em outro Virtual Host

---

# 9. Virtual Host Fuzzing

Foi realizado fuzzing de VHosts.

```bash
ffuf \
-u http://IP:PORT \
-H "Host: FUZZ.fuzzing_fun.htb" \
-w /usr/share/seclists/Discovery/Web-Content/common.txt \
-mc all
```

### Resultado

```text
hidden.fuzzing_fun.htb
```

---

# 10. Novo Virtual Host

Adicionamos o novo host:

```bash
echo "IP hidden.fuzzing_fun.htb" | sudo tee -a /etc/hosts
```

---

# 11. Explorando o Diretório godeep

Ao acessar:

```bash
http://hidden.fuzzing_fun.htb:PORT/godeep/
```

Recebemos uma mensagem indicando que estávamos próximos.

---

# 12. Enumeração Profunda (Recursiva)

A partir desse ponto foi realizado fuzzing sucessivo dentro dos diretórios descobertos.

## Primeiro nível

```bash
ffuf \
-u http://hidden.fuzzing_fun.htb:PORT/godeep/FUZZ \
-w /usr/share/seclists/Discovery/Web-Content/common.txt
```

Resultado:

```text
stoneedge
```

---

## Segundo nível

```bash
ffuf \
-u http://hidden.fuzzing_fun.htb:PORT/godeep/stoneedge/FUZZ \
-w /usr/share/seclists/Discovery/Web-Content/common.txt
```

Resultado:

```text
bbclone
```

---

## Terceiro nível

```bash
ffuf \
-u http://hidden.fuzzing_fun.htb:PORT/godeep/stoneedge/bbclone/FUZZ \
-w /usr/share/seclists/Discovery/Web-Content/common.txt
```

Resultado:

```text
typo3
```

---

# 13. Flag

Ao acessar:

```text
http://hidden.fuzzing_fun.htb:PORT/godeep/stoneedge/bbclone/typo3/
```

Foi apresentada a página contendo a flag final do desafio.

---

# Key Takeaways

Este laboratório reforçou a importância de:

* Não confiar apenas em enumeração básica.
* Realizar fuzzing com extensões específicas.
* Investigar mensagens de erro.
* Fuzzar valores de parâmetros.
* Utilizar filtros para reduzir ruído.
* Enumerar Virtual Hosts.
* Seguir pistas fornecidas pela aplicação.
* Aplicar enumeração recursiva de forma sistemática.

O Skills Assessment serve como uma excelente revisão prática dos conceitos abordados durante todo o módulo de Web Fuzzing da HTB Academy.
