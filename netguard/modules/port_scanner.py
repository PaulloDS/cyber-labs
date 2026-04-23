"""
Módulo 1 — Port Scanner
========================
Varre portas TCP de um host alvo, identifica serviços
e alerta sobre portas consideradas de risco.
"""

import socket
import threading
from datetime import datetime
from queue import Queue


# Portas consideradas sensíveis ou de alto risco
RISKY_PORTS = {
    21:   ("FTP",         "HIGH",   "Transferência de arquivos sem criptografia"),
    22:   ("SSH",         "LOW",    "Acesso remoto seguro — verificar versão e configuração"),
    23:   ("Telnet",      "HIGH",   "Protocolo legado sem criptografia — substituir por SSH"),
    25:   ("SMTP",        "MEDIUM", "Servidor de e-mail — verificar relay aberto"),
    53:   ("DNS",         "MEDIUM", "Verificar se está exposto publicamente sem necessidade"),
    80:   ("HTTP",        "MEDIUM", "Tráfego não criptografado — considerar HTTPS"),
    110:  ("POP3",        "MEDIUM", "E-mail sem criptografia"),
    135:  ("RPC",         "HIGH",   "Vetor comum de exploração no Windows"),
    139:  ("NetBIOS",     "HIGH",   "Compartilhamento legado — vetor de ataque lateral"),
    143:  ("IMAP",        "MEDIUM", "E-mail sem criptografia"),
    443:  ("HTTPS",       "LOW",    "Tráfego criptografado — verificar certificado e versão TLS"),
    445:  ("SMB",         "HIGH",   "Compartilhamento de arquivos — alvo frequente de ransomware"),
    1433: ("MSSQL",       "HIGH",   "Banco de dados — nunca deve ficar exposto publicamente"),
    1521: ("Oracle DB",   "HIGH",   "Banco de dados — nunca deve ficar exposto publicamente"),
    3306: ("MySQL",       "HIGH",   "Banco de dados — nunca deve ficar exposto publicamente"),
    3389: ("RDP",         "HIGH",   "Área de trabalho remota — alvo frequente de brute force"),
    5432: ("PostgreSQL",  "HIGH",   "Banco de dados — nunca deve ficar exposto publicamente"),
    5900: ("VNC",         "HIGH",   "Acesso remoto sem criptografia forte"),
    6379: ("Redis",       "HIGH",   "Banco em memória — frequentemente exposto sem autenticação"),
    8080: ("HTTP-Alt",    "MEDIUM", "Porta alternativa HTTP — verificar o que está servindo"),
    8443: ("HTTPS-Alt",   "LOW",    "Porta alternativa HTTPS"),
    27017:("MongoDB",     "HIGH",   "Banco de dados — frequentemente exposto sem autenticação"),
}

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
SEVERITY_COLOR = {"HIGH": "\033[91m", "MEDIUM": "\033[93m", "LOW": "\033[92m", "INFO": "\033[94m"}
RESET = "\033[0m"


def _parse_port_range(port_range: str) -> list[int]:
    """Converte string de portas em lista de inteiros."""
    ports = []
    for part in port_range.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


class PortScanner:
    def __init__(self, target: str, port_range: str = "1-1024",
                 timeout: float = 0.5, threads: int = 100):
        self.target = target
        self.port_range = port_range
        self.timeout = timeout
        self.threads = threads
        self._open_ports: list[int] = []
        self._queue = Queue()
        self._lock = threading.Lock()

    def _resolve_target(self) -> str:
        try:
            return socket.gethostbyname(self.target)
        except socket.gaierror:
            raise ValueError(f"Não foi possível resolver o host: {self.target}")

    def _scan_port(self, ip: str, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                return s.connect_ex((ip, port)) == 0
        except Exception:
            return False

    def _worker(self, ip: str):
        while not self._queue.empty():
            port = self._queue.get()
            if self._scan_port(ip, port):
                with self._lock:
                    self._open_ports.append(port)
            self._queue.task_done()

    def scan(self) -> dict:
        ip = self._resolve_target()
        ports = _parse_port_range(self.port_range)

        for p in ports:
            self._queue.put(p)

        start = datetime.now()
        workers = []
        for _ in range(min(self.threads, len(ports))):
            t = threading.Thread(target=self._worker, args=(ip,), daemon=True)
            t.start()
            workers.append(t)

        self._queue.join()
        elapsed = (datetime.now() - start).total_seconds()

        open_sorted = sorted(self._open_ports)
        findings = []
        for port in open_sorted:
            if port in RISKY_PORTS:
                service, severity, note = RISKY_PORTS[port]
            else:
                service = self._try_get_service(port)
                severity = "INFO"
                note = "Porta aberta — verificar necessidade de exposição"
            findings.append({
                "port": port,
                "service": service,
                "severity": severity,
                "note": note,
            })

        return {
            "module": "Port Scanner",
            "target": self.target,
            "ip": ip,
            "ports_scanned": len(ports),
            "open_ports": len(open_sorted),
            "elapsed": round(elapsed, 2),
            "findings": sorted(findings, key=lambda x: SEVERITY_ORDER[x["severity"]]),
        }

    @staticmethod
    def _try_get_service(port: int) -> str:
        try:
            return socket.getservbyport(port, "tcp")
        except OSError:
            return "unknown"

    @staticmethod
    def print_results(results: dict):
        print(f"\n  Alvo  : {results['target']} ({results['ip']})")
        print(f"  Portas: {results['ports_scanned']} verificadas em {results['elapsed']}s")
        print(f"  Abertas: {results['open_ports']}\n")

        if not results["findings"]:
            print("  [✓] Nenhuma porta aberta encontrada no range verificado.\n")
            return

        print(f"  {'PORTA':<8} {'SERVIÇO':<14} {'SEVERIDADE':<10} OBSERVAÇÃO")
        print(f"  {'-'*70}")
        for f in results["findings"]:
            color = SEVERITY_COLOR.get(f["severity"], "")
            print(f"  {f['port']:<8} {f['service']:<14} "
                  f"{color}{f['severity']:<10}{RESET} {f['note']}")
        print()
