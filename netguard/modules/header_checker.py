"""
Módulo 2 — HTTP Security Header Checker
=========================================
Verifica se os headers de segurança HTTP estão presentes
e corretamente configurados em um servidor web alvo.
"""

import urllib.request
import urllib.error
import ssl
from datetime import datetime


# Definição dos headers de segurança esperados
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "HSTS — força conexões HTTPS e previne downgrade attacks",
        "recommendation": "Adicionar: Strict-Transport-Security: max-age=31536000; includeSubDomains",
        "check": lambda v: "max-age" in v.lower(),
        "check_msg": "Verifique se max-age está definido (mínimo recomendado: 31536000)"
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "CSP — previne ataques XSS e injeção de conteúdo",
        "recommendation": "Definir uma política CSP restritiva. Ex: default-src 'self'",
        "check": lambda v: len(v) > 5,
        "check_msg": "Política CSP parece muito permissiva ou vazia"
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Previne ataques de Clickjacking via iframes",
        "recommendation": "Adicionar: X-Frame-Options: DENY ou SAMEORIGIN",
        "check": lambda v: v.upper() in ("DENY", "SAMEORIGIN"),
        "check_msg": "Valor deve ser DENY ou SAMEORIGIN"
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "Previne MIME-type sniffing pelo navegador",
        "recommendation": "Adicionar: X-Content-Type-Options: nosniff",
        "check": lambda v: v.lower() == "nosniff",
        "check_msg": "Valor deve ser 'nosniff'"
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Controla informações de referência enviadas nas requisições",
        "recommendation": "Adicionar: Referrer-Policy: no-referrer ou strict-origin-when-cross-origin",
        "check": lambda v: v.lower() in (
            "no-referrer", "strict-origin", "strict-origin-when-cross-origin",
            "no-referrer-when-downgrade", "same-origin"
        ),
        "check_msg": "Considere usar 'no-referrer' ou 'strict-origin-when-cross-origin'"
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "Controla acesso a APIs do navegador (câmera, microfone, geolocalização etc.)",
        "recommendation": "Adicionar: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        "check": lambda v: len(v) > 3,
        "check_msg": "Política parece muito permissiva"
    },
    "X-XSS-Protection": {
        "severity": "LOW",
        "description": "Header legado de proteção XSS (substituído pelo CSP em navegadores modernos)",
        "recommendation": "Adicionar: X-XSS-Protection: 1; mode=block (ou remover em favor do CSP)",
        "check": lambda v: "1" in v,
        "check_msg": "Considere usar '1; mode=block'"
    },
}

# Headers que NÃO deveriam estar expostos
LEAKY_HEADERS = {
    "Server":          "Expõe informações do servidor web (versão, software)",
    "X-Powered-By":    "Expõe tecnologia backend (PHP, ASP.NET, Express etc.)",
    "X-AspNet-Version":"Expõe versão do ASP.NET",
    "X-Generator":     "Expõe o CMS ou gerador do site",
}

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
SEVERITY_COLOR = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[92m", "INFO": "\033[94m"}
RESET = "\033[0m"


class HeaderChecker:
    def __init__(self, target: str, timeout: int = 10):
        self.target = self._normalize_url(target)
        self.timeout = timeout

    @staticmethod
    def _normalize_url(url: str) -> str:
        if not url.startswith(("http://", "https://")):
            return f"https://{url}"
        return url

    def _fetch_headers(self) -> dict:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            self.target,
            headers={"User-Agent": "NetGuard-SecurityAudit/1.0"}
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                return dict(resp.headers), resp.status
        except urllib.error.HTTPError as e:
            return dict(e.headers), e.code
        except Exception as e:
            raise ConnectionError(f"Não foi possível conectar em {self.target}: {e}")

    def check(self) -> dict:
        raw_headers, status_code = self._fetch_headers()
        # Normalizar chaves para case-insensitive
        headers = {k.lower(): v for k, v in raw_headers.items()}

        findings = []
        score = 0
        max_score = 0

        # Verificar headers de segurança esperados
        for header, config in SECURITY_HEADERS.items():
            max_score += 1
            header_lower = header.lower()
            present = header_lower in headers

            if present:
                value = headers[header_lower]
                valid = config["check"](value)
                if valid:
                    score += 1
                    status = "PRESENT_VALID"
                    severity = "INFO"
                    note = f"✓ Configurado corretamente: {value[:60]}"
                else:
                    status = "PRESENT_INVALID"
                    severity = config["severity"]
                    note = f"⚠ Presente mas mal configurado — {config['check_msg']}"
            else:
                status = "MISSING"
                severity = config["severity"]
                note = f"✗ Ausente — {config['recommendation']}"

            findings.append({
                "header": header,
                "status": status,
                "severity": severity,
                "description": config["description"],
                "note": note,
                "value": headers.get(header_lower, "—"),
            })

        # Verificar headers que vazam informações
        leaked = []
        for header, risk in LEAKY_HEADERS.items():
            if header.lower() in headers:
                leaked.append({
                    "header": header,
                    "value": headers[header.lower()],
                    "risk": risk,
                })

        # Verificar HTTPS
        uses_https = self.target.startswith("https://")

        grade = self._calculate_grade(score, max_score)

        return {
            "module": "HTTP Header Checker",
            "target": self.target,
            "status_code": status_code,
            "uses_https": uses_https,
            "score": score,
            "max_score": max_score,
            "grade": grade,
            "findings": sorted(findings, key=lambda x: SEVERITY_ORDER[x["severity"]]),
            "leaked_headers": leaked,
        }

    @staticmethod
    def _calculate_grade(score: int, max_score: int) -> str:
        ratio = score / max_score if max_score > 0 else 0
        if ratio >= 0.85: return "A"
        if ratio >= 0.70: return "B"
        if ratio >= 0.55: return "C"
        if ratio >= 0.40: return "D"
        return "F"

    @staticmethod
    def print_results(results: dict):
        grade_color = {
            "A": "\033[92m", "B": "\033[92m", "C": "\033[93m",
            "D": "\033[91m", "F": "\033[91m"
        }
        RESET = "\033[0m"

        print(f"\n  Alvo       : {results['target']}")
        print(f"  HTTP Status: {results['status_code']}")
        print(f"  HTTPS      : {'✓ Sim' if results['uses_https'] else '✗ Não — tráfego não criptografado!'}")
        g = results['grade']
        print(f"  Score      : {results['score']}/{results['max_score']} — "
              f"Nota: {grade_color.get(g, '')}{g}{RESET}\n")

        print(f"  {'HEADER':<35} {'STATUS':<18} OBSERVAÇÃO")
        print(f"  {'-'*80}")
        for f in results["findings"]:
            color = SEVERITY_COLOR.get(f["severity"], "")
            status_label = {
                "PRESENT_VALID":   "✓ OK",
                "PRESENT_INVALID": "⚠ Mal configurado",
                "MISSING":         "✗ Ausente",
            }.get(f["status"], f["status"])
            print(f"  {f['header']:<35} {color}{status_label:<18}{RESET} {f['note'][:50]}")

        if results["leaked_headers"]:
            print(f"\n  \033[91m[!] Headers que expõem informações do servidor:\033[0m")
            for lh in results["leaked_headers"]:
                print(f"      {lh['header']}: {lh['value'][:40]}  →  {lh['risk']}")
        print()


SEVERITY_COLOR = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[92m", "INFO": "\033[94m"}
