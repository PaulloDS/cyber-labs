"""
Módulo 3 — Network Device Inventory
=====================================
Descobre hosts ativos em uma rede local via ping sweep,
mapeia IPs, tenta resolver hostnames e identifica serviços
comuns para montar um inventário da rede.
"""

import socket
import subprocess
import platform
import threading
from ipaddress import ip_network, IPv4Network
from datetime import datetime
from queue import Queue


# Portas comuns para identificação rápida de tipo de dispositivo
DEVICE_FINGERPRINT_PORTS = {
    22:   "SSH",
    23:   "Telnet",
    80:   "HTTP",
    443:  "HTTPS",
    445:  "SMB",
    3389: "RDP",
    8080: "HTTP-Alt",
}


def _ping(host: str, timeout: int = 1) -> bool:
    """Pinga um host e retorna True se responder."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
    else:
        cmd = ["ping", "-c", "1", "-W", str(timeout), host]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout + 1
        )
        return result.returncode == 0
    except Exception:
        return False


def _resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return "—"


def _quick_port_check(ip: str, port: int, timeout: float = 0.3) -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            return s.connect_ex((ip, port)) == 0
    except Exception:
        return False


def _fingerprint_device(ip: str) -> list[str]:
    """Verifica portas comuns para identificar serviços no host."""
    open_services = []
    for port, service in DEVICE_FINGERPRINT_PORTS.items():
        if _quick_port_check(ip, port):
            open_services.append(f"{service}:{port}")
    return open_services


class NetworkInventory:
    def __init__(self, network: str, threads: int = 50, ping_timeout: int = 1):
        self.network = network
        self.threads = threads
        self.ping_timeout = ping_timeout
        self._active_hosts: list[str] = []
        self._queue = Queue()
        self._lock = threading.Lock()

    def _worker(self):
        while not self._queue.empty():
            ip = self._queue.get()
            if _ping(str(ip), self.ping_timeout):
                with self._lock:
                    self._active_hosts.append(str(ip))
            self._queue.task_done()

    def _validate_network(self) -> IPv4Network:
        try:
            return ip_network(self.network, strict=False)
        except ValueError:
            raise ValueError(f"Rede inválida: {self.network}. Use formato CIDR (ex: 192.168.1.0/24)")

    def scan(self) -> dict:
        net = self._validate_network()
        hosts = list(net.hosts())

        if len(hosts) > 512:
            raise ValueError("Rede muito grande. Use uma sub-rede /23 ou menor.")

        print(f"  Verificando {len(hosts)} endereços em {self.network}...")

        for host in hosts:
            self._queue.put(host)

        start = datetime.now()
        workers = []
        for _ in range(min(self.threads, len(hosts))):
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            workers.append(t)

        self._queue.join()
        elapsed = (datetime.now() - start).total_seconds()

        # Para cada host ativo, enriquecer com hostname e serviços
        inventory = []
        print(f"  Enriquecendo dados de {len(self._active_hosts)} host(s) ativo(s)...")
        for ip in sorted(self._active_hosts, key=lambda x: tuple(int(p) for p in x.split("."))):
            hostname = _resolve_hostname(ip)
            services = _fingerprint_device(ip)
            device_type = _guess_device_type(services)
            inventory.append({
                "ip": ip,
                "hostname": hostname,
                "services": services,
                "device_type": device_type,
            })

        return {
            "module": "Network Inventory",
            "network": self.network,
            "total_hosts": len(hosts),
            "active_hosts": len(inventory),
            "elapsed": round(elapsed, 2),
            "inventory": inventory,
        }

    @staticmethod
    def print_results(results: dict):
        print(f"\n  Rede     : {results['network']}")
        print(f"  Hosts    : {results['active_hosts']} ativos de {results['total_hosts']} "
              f"em {results['elapsed']}s\n")

        if not results["inventory"]:
            print("  Nenhum host ativo encontrado.\n")
            return

        print(f"  {'IP':<18} {'HOSTNAME':<30} {'TIPO':<18} SERVIÇOS DETECTADOS")
        print(f"  {'-'*80}")
        for host in results["inventory"]:
            services_str = ", ".join(host["services"]) if host["services"] else "nenhum detectado"
            print(f"  {host['ip']:<18} {host['hostname']:<30} {host['device_type']:<18} {services_str}")
        print()


def _guess_device_type(services: list[str]) -> str:
    service_names = [s.split(":")[0] for s in services]
    if "RDP" in service_names:
        return "Windows Workstation"
    if "SMB" in service_names and "SSH" not in service_names:
        return "Windows Server"
    if "SSH" in service_names and "HTTP" in service_names:
        return "Linux Server"
    if "SSH" in service_names:
        return "Linux/Network Device"
    if "HTTP" in service_names or "HTTPS" in service_names:
        return "Web Server"
    if "Telnet" in service_names:
        return "Network Device (legado)"
    if services:
        return "Host Desconhecido"
    return "Host (sem serviços visíveis)"
