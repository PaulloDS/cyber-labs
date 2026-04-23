"""
Módulo 4 — Log Analyzer
=========================
Analisa arquivos de log em busca de padrões suspeitos:
tentativas de brute force, acessos negados, IPs maliciosos,
erros críticos e outros indicadores de comprometimento.
"""

import re
from collections import defaultdict, Counter
from datetime import datetime
from pathlib import Path


# ── Padrões de regex por tipo de log ──────────────────────────────────────

PATTERNS = {
    "auth": {
        # SSH failed password: "Failed password for root from 192.168.1.100 port 22"
        "failed_login": re.compile(
            r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)"
        ),
        # Successful login
        "success_login": re.compile(
            r"Accepted (?:password|publickey) for (\S+) from ([\d.]+) port (\d+)"
        ),
        # Invalid user
        "invalid_user": re.compile(
            r"Invalid user (\S+) from ([\d.]+)"
        ),
        # sudo usage
        "sudo": re.compile(
            r"sudo:\s+(\S+) : .* COMMAND=(.*)"
        ),
        # PAM authentication failure
        "pam_failure": re.compile(
            r"pam_unix.*authentication failure.*rhost=([\d.]+)"
        ),
    },
    "apache": {
        # Apache combined log format
        "access": re.compile(
            r'([\d.]+) .+ .+ \[(.+)\] "(\S+) (\S+) \S+" (\d+) \d+'
        ),
        # Error log
        "error": re.compile(
            r'\[(\w+ \w+ \d+ [\d:]+\.\d+ \d+)\] \[(\w+)\] .+ ([\d.]+)'
        ),
    },
    "generic": {
        "error": re.compile(r"(ERROR|CRITICAL|FATAL|ALERT)", re.IGNORECASE),
        "warning": re.compile(r"(WARNING|WARN)", re.IGNORECASE),
        "ip": re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3})\b"),
    }
}

# Threshold para considerar brute force
BRUTE_FORCE_THRESHOLD = 5


class LogAnalyzer:
    def __init__(self, logfile: str, log_type: str = "auth"):
        self.logfile = Path(logfile)
        self.log_type = log_type

    def _read_file(self) -> list[str]:
        if not self.logfile.exists():
            raise FileNotFoundError(f"Arquivo não encontrado: {self.logfile}")
        try:
            with open(self.logfile, "r", encoding="utf-8", errors="replace") as f:
                return f.readlines()
        except PermissionError:
            raise PermissionError(f"Sem permissão para ler: {self.logfile}. Tente com sudo.")

    def analyze(self) -> dict:
        lines = self._read_file()
        if self.log_type == "auth":
            return self._analyze_auth(lines)
        elif self.log_type == "apache":
            return self._analyze_apache(lines)
        else:
            return self._analyze_generic(lines)

    def _analyze_auth(self, lines: list[str]) -> dict:
        failed_by_ip = defaultdict(int)
        failed_by_user = defaultdict(int)
        success_logins = []
        invalid_users = []
        sudo_commands = []
        pam_failures = defaultdict(int)

        patterns = PATTERNS["auth"]

        for line in lines:
            # Failed logins
            m = patterns["failed_login"].search(line)
            if m:
                user, ip, port = m.groups()
                failed_by_ip[ip] += 1
                failed_by_user[user] += 1
                continue

            # Successful logins
            m = patterns["success_login"].search(line)
            if m:
                user, ip, port = m.groups()
                success_logins.append({"user": user, "ip": ip, "port": port,
                                       "line": line.strip()})
                continue

            # Invalid users
            m = patterns["invalid_user"].search(line)
            if m:
                user, ip = m.groups()
                invalid_users.append({"user": user, "ip": ip})
                continue

            # Sudo
            m = patterns["sudo"].search(line)
            if m:
                user, command = m.groups()
                sudo_commands.append({"user": user, "command": command.strip()})

            # PAM failures
            m = patterns["pam_failure"].search(line)
            if m:
                ip = m.group(1)
                pam_failures[ip] += 1

        # Detectar brute force
        brute_force_ips = {
            ip: count for ip, count in failed_by_ip.items()
            if count >= BRUTE_FORCE_THRESHOLD
        }

        # Gerar findings
        findings = []

        for ip, count in sorted(brute_force_ips.items(), key=lambda x: -x[1]):
            severity = "HIGH" if count >= 20 else "MEDIUM"
            findings.append({
                "type": "Brute Force Detectado",
                "severity": severity,
                "detail": f"IP {ip} teve {count} tentativas de login falhas",
                "ip": ip,
                "count": count,
            })

        for login in success_logins:
            findings.append({
                "type": "Login Bem-sucedido",
                "severity": "INFO",
                "detail": f"Usuário '{login['user']}' autenticado de {login['ip']}",
                "ip": login["ip"],
            })

        if invalid_users:
            top_invalid = Counter(u["user"] for u in invalid_users).most_common(5)
            for user, count in top_invalid:
                findings.append({
                    "type": "Usuário Inválido",
                    "severity": "MEDIUM",
                    "detail": f"Usuário inexistente '{user}' tentado {count} vezes",
                    "count": count,
                })

        return {
            "module": "Log Analyzer",
            "logfile": str(self.logfile),
            "log_type": "auth",
            "total_lines": len(lines),
            "total_failed_logins": sum(failed_by_ip.values()),
            "total_success_logins": len(success_logins),
            "brute_force_ips": brute_force_ips,
            "top_failed_users": dict(Counter(failed_by_user).most_common(5)),
            "sudo_commands": sudo_commands,
            "findings": sorted(findings, key=lambda x: {"HIGH": 0, "MEDIUM": 1, "INFO": 2}[x["severity"]]),
        }

    def _analyze_apache(self, lines: list[str]) -> dict:
        status_counter = Counter()
        ip_counter = Counter()
        error_lines = []
        findings = []

        for line in lines:
            m = PATTERNS["apache"]["access"].search(line)
            if m:
                ip, dt, method, path, status = m.groups()
                status_counter[status] += 1
                ip_counter[ip] += 1
                if status in ("401", "403", "404", "500"):
                    error_lines.append({"ip": ip, "method": method, "path": path, "status": status})

        # IPs com muitos erros 4xx podem ser scanners
        for ip, count in ip_counter.most_common(10):
            if count > 50:
                findings.append({
                    "type": "Alto Volume de Requisições",
                    "severity": "MEDIUM",
                    "detail": f"IP {ip} fez {count} requisições — possível scanner",
                    "ip": ip,
                    "count": count,
                })

        return {
            "module": "Log Analyzer",
            "logfile": str(self.logfile),
            "log_type": "apache",
            "total_lines": len(lines),
            "status_distribution": dict(status_counter.most_common(10)),
            "top_ips": dict(ip_counter.most_common(10)),
            "findings": findings,
        }

    def _analyze_generic(self, lines: list[str]) -> dict:
        errors = []
        warnings = []
        all_ips = Counter()
        findings = []

        for i, line in enumerate(lines, 1):
            if PATTERNS["generic"]["error"].search(line):
                errors.append({"line_num": i, "content": line.strip()[:120]})
            elif PATTERNS["generic"]["warning"].search(line):
                warnings.append({"line_num": i, "content": line.strip()[:120]})

            for ip in PATTERNS["generic"]["ip"].findall(line):
                # Filtrar IPs privados e localhost para foco externo
                if not ip.startswith(("127.", "0.", "255.")):
                    all_ips[ip] += 1

        if errors:
            findings.append({
                "type": "Erros Críticos",
                "severity": "HIGH" if len(errors) > 10 else "MEDIUM",
                "detail": f"{len(errors)} linhas de erro encontradas no log",
                "count": len(errors),
            })

        return {
            "module": "Log Analyzer",
            "logfile": str(self.logfile),
            "log_type": "generic",
            "total_lines": len(lines),
            "total_errors": len(errors),
            "total_warnings": len(warnings),
            "top_ips": dict(all_ips.most_common(10)),
            "sample_errors": errors[:10],
            "findings": findings,
        }

    @staticmethod
    def print_results(results: dict):
        RESET = "\033[0m"
        RED = "\033[91m"
        YELLOW = "\033[93m"
        GREEN = "\033[92m"
        BLUE = "\033[94m"

        print(f"\n  Arquivo : {results['logfile']}")
        print(f"  Tipo    : {results['log_type']}")
        print(f"  Linhas  : {results['total_lines']:,}\n")

        if results["log_type"] == "auth":
            print(f"  Logins falhos  : {RED}{results['total_failed_logins']}{RESET}")
            print(f"  Logins ok      : {GREEN}{results['total_success_logins']}{RESET}")

            if results.get("brute_force_ips"):
                print(f"\n  {RED}[!] IPs com possível Brute Force:{RESET}")
                for ip, count in sorted(results["brute_force_ips"].items(), key=lambda x: -x[1]):
                    print(f"      {ip:<20} {count} tentativas")

            if results.get("top_failed_users"):
                print(f"\n  Usuários mais atacados:")
                for user, count in results["top_failed_users"].items():
                    print(f"      {user:<20} {count} tentativas")

        findings = results.get("findings", [])
        if findings:
            print(f"\n  {'TIPO':<30} {'SEVERIDADE':<12} DETALHE")
            print(f"  {'-'*75}")
            color_map = {"HIGH": RED, "MEDIUM": YELLOW, "INFO": BLUE}
            for f in findings:
                color = color_map.get(f["severity"], "")
                print(f"  {f['type']:<30} {color}{f['severity']:<12}{RESET} {f['detail'][:50]}")
        else:
            print(f"  {GREEN}[✓] Nenhum padrão suspeito encontrado.{RESET}")
        print()
