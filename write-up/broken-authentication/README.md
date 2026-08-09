# 🔐 Authentication Bypass via Direct Access — HTB Academy Skills Assessment

![HTB Academy](https://img.shields.io/badge/HTB%20Academy-Broken%20Authentication-9FEF00?style=for-the-badge&logo=hackthebox)
![Status](https://img.shields.io/badge/Status-Concluído-success?style=for-the-badge)
![Category](https://img.shields.io/badge/Category-Web%20Penetration%20Tester-blue?style=for-the-badge)

> Write-up do Skills Assessment do módulo **Broken Authentication** da trilha CWES (HTB Academy), documentando a exploração de uma falha de controle de acesso que permitiu contornar completamente a etapa de autenticação em dois fatores (2FA).

---

## 📑 Índice

- [Introdução](#-introdução)
- [Reconhecimento da Aplicação](#-reconhecimento-da-aplicação)
- [Enumeração de Usuários](#-enumeração-de-usuários)
- [Brute Force de Senha](#-brute-force-de-senha)
- [Investigação do Mecanismo de OTP](#-investigação-do-mecanismo-de-otp)
- [Descobrindo a Vulnerabilidade](#-descobrindo-a-vulnerabilidade)
- [Exploração](#-exploração)
- [Vulnerabilidade Encontrada](#-vulnerabilidade-encontrada)
- [Lições Aprendidas](#-lições-aprendidas)
- [Skills Desenvolvidas](#-skills-desenvolvidas)
- [Disclaimer Ético](#-disclaimer-ético)

---

## 🎯 Introdução

O objetivo deste Skills Assessment era avaliar vulnerabilidades no processo de autenticação da aplicação web da empresa fictícia. A aplicação utilizava um fluxo aparentemente robusto: login com usuário e senha seguido de uma etapa obrigatória de **autenticação em dois fatores (2FA)** via código OTP.

A vulnerabilidade explorável, no entanto, não estava na implementação do OTP e sim na forma como a aplicação tratava o **controle de acesso a recursos protegidos**.

> <img src="https://i.imgur.com/ybhfUfC.png"/>

---

## 🔍 Reconhecimento da Aplicação

Duas funcionalidades principais foram identificadas:

- Login de usuários
- Registro de novas contas

Após um registro e login com sucesso, a aplicação redirecionava automaticamente para `profile.php`, exibindo uma mensagem de boas-vindas **sem solicitar código OTP**. Esse detalhe, observado logo no início, inicialmente não pareceu relevante, mas viria a ser a peça-chave da exploração.

> <img src="https://i.imgur.com/3cBjwwc.png"/>

---

## 🕵️ Enumeração de Usuários

Seguindo a metodologia do módulo, usuários válidos foram enumerados através das mensagens de erro retornadas pela aplicação durante tentativas de login.

```bash
ffuf -w usernames.txt -X POST \
  -d "username=FUZZ&password=invalid" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u http://TARGET_IP/login.php \
  -fr "Unknown username or password."
```

Isso permitiu restringir o ataque de força bruta apenas às contas válidas identificadas.

> <img src="https://i.imgur.com/DnIb5Hz.png"/>

---

## 🔑 Brute Force de Senha

Com um usuário válido em mãos, foi realizado um ataque de força bruta contra a senha:

```bash
ffuf -w rockyou.txt -X POST \
  -d "username=USUARIO_VALIDO&password=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u http://TARGET_IP/login.php \
  -fr "Invalid credentials."
```

A senha correta foi descoberta. 

> <img src="https://i.imgur.com/KZsXV0W.png"/>

No entanto, ao submeter as credenciais válidas, a aplicação passou a exigir um **código OTP**.

> <img src="https://i.imgur.com/OUEztJy.png"/>

---

## 🧩 Investigação do Mecanismo de OTP

A primeira hipótese, natural após o conteúdo do módulo, foi que o OTP seria quebrável via força bruta. Diversas abordagens foram testadas:

- ➤ Brute force do código com `ffuf`
- ➤ Automação completa do fluxo login → OTP
- ➤ Reutilização de sessão e cookies PHP
- ➤ Análise de respostas HTTP em busca de campos ocultos
- ➤ Inspeção dos parâmetros enviados na autenticação

Observações relevantes durante os testes:

- Após 3 códigos inválidos, a aplicação redirecionava novamente para o login
- Era possível autenticar-se novamente de imediato
- O cookie de sessão permanecia o mesmo, sem rotação
- Não existiam parâmetros ocultos relacionados ao OTP

Mesmo com o processo totalmente automatizado, nenhum código válido foi encontrado e ficou claro que o brute force do OTP **não era o vetor pretendido** pelo laboratório.

---

## 💡 Descobrindo a Vulnerabilidade

Revisando o comportamento observado desde o início, o redirecionamento automático para `/profile.php` logo após o login de um novo registro voltou à tona. Isso levou ao teste seguinte.

**Testando Direct Access:** ainda no estado em que a aplicação solicitava o OTP, foi feita uma tentativa de acesso direto a `/profile.php`. O navegador exibia um redirecionamento para a página de 2FA, aparentemente bloqueado.

Relembrando o tópico *Authentication Bypass via Direct Access* do módulo, a resposta HTTP foi interceptada com o **Burp Suite**.
Embora o servidor respondesse com um redirecionamento (302), o **corpo da resposta já trazia todo o conteúdo protegido** e o navegador simplesmente ocultava isso ao seguir o redirect automaticamente.

> <img src="https://i.imgur.com/PnVFyva.png"/>

Esse comportamento reflete exatamente uma falha clássica de implementação em PHP:

```php
// Código vulnerável
if (!$_SESSION['active']) {
    header("Location: index.php");
}
// segue processando e enviando o restante da página...
```

```php
// Implementação correta
if (!$_SESSION['active']) {
    header("Location: index.php");
    exit;
}
```

A ausência do `exit()` após o `header()` permitia que o script continuasse executando e enviasse informações protegidas ao cliente, mesmo sem autenticação concluída.

---

## ⚔️ Exploração

Passo a passo da exploração, via Burp Suite:

1. Autenticar-se com usuário e senha descobertos
2. Permanecer na tela de solicitação do OTP (sem informá-lo)
3. Interceptar a requisição de acesso a `profile.php`
4. Observar a resposta `302 Found`
5. Analisar o corpo da resposta **antes** do navegador seguir o redirecionamento
6. Localizar a flag no conteúdo protegido retornado

Não foi necessário descobrir o código OTP em nenhum momento.

> <img src="https://i.imgur.com/oZTsPae.png"/>

---

## 🐛 Vulnerabilidade Encontrada

**Authentication Bypass via Direct Access**: apesar de tentar redirecionar usuários não autenticados para a etapa de 2FA, o servidor continuava processando o script da página protegida e enviava seu conteúdo completo antes da execução do redirecionamento pelo navegador.

Qualquer atacante capaz de interceptar a resposta HTTP conseguiria visualizar informações protegidas **sem concluir a autenticação em dois fatores**.

---

## 📚 Lições Aprendidas

Este Skills Assessment reforçou a importância de compreender o funcionamento da aplicação como um todo, e não apenas insistir na última funcionalidade analisada. Embora a presença do OTP levasse naturalmente à hipótese de brute force, a vulnerabilidade real estava em outra etapa do fluxo, na implementação incorreta do controle de acesso a recursos protegidos.

Detalhes aparentemente irrelevantes, observados no início da análise, podem se tornar fundamentais para identificar a vulnerabilidade correta. Compreender o protocolo HTTP e inspecionar cuidadosamente as respostas do servidor em vez de confiar apenas no comportamento exibido pelo navegador pode revelar falhas invisíveis durante a navegação comum.

---

## 🛠️ Skills Desenvolvidas

- Enumeração de usuários via mensagens de erro
- Brute force de credenciais com `ffuf`
- Análise de mecanismos de OTP/2FA
- Interceptação e análise de respostas HTTP com Burp Suite
- Identificação de falhas de controle de acesso por ausência de `exit()` após `header()`
- Authentication Bypass via Direct Access

---

## ⚖️ Disclaimer Ético

Este write-up documenta atividades realizadas **exclusivamente em ambiente de laboratório controlado e autorizado** da plataforma HTB Academy, como parte das certificações CWES e CPTS. Nenhuma técnica aqui descrita deve ser aplicada contra sistemas sem autorização explícita. O conteúdo tem fins educacionais e de desenvolvimento profissional em segurança ofensiva.

---

*Write-up produzido como parte da jornada das certificações CWES e CPTS (HTB Academy).*
