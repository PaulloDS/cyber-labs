#!/usr/bin/env python3
"""
NetGuard — Network Security Audit Toolkit
==========================================
Toolkit modular de auditoria de segurança de redes.
Uso: python main.py --help
"""

import argparse
import sys
import os
from datetime import datetime

from modules.port_scanner import PortScanner
from modules.header_checker import HeaderChecker
from modules.network_inventory import NetworkInventory
from modules.log_analyzer import LogAnalyzer
from modules.report_generator import ReportGenerator


BANNER = r"""
 _   _      _    ____                      _
| \ | | ___| |_ / ___|_   _  __ _ _ __ __| |
|  \| |/ _ \ __| |  _| | | |/ _` | '__/ _` |
| |\  |  __/ |_| |_| | |_| | (_| | | | (_| |
|_| \_|\___|\__|\____|\__,_|\__,_|_|  \__,_|

  Network Security Audit Toolkit v1.0
  by [Seu Nome] | github.com/seuperfil
"""


def parse_args():
    parser = argparse.ArgumentParser(
        description="NetGuard — Network Security Audit Toolkit",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Módulos disponíveis")

    # ── port-scan ──────────────────────────────────────────────────────────
    ps = subparsers.add_parser("port-scan", help="Varre portas de um host")
    ps.add_argument("target", help="IP ou hostname alvo (ex: 192.168.1.1)")
    ps.add_argument("--ports", default="1-1024",
                    help="Range de portas (ex: 1-1024 ou 22,80,443). Padrão: 1-1024")
    ps.add_argument("--timeout", type=float, default=0.5,
                    help="Timeout por porta em segundos. Padrão: 0.5")

    # ── header-check ──────────────────────────────────────────────────────
    hc = subparsers.add_parser("header-check", help="Verifica headers HTTP de segurança")
    hc.add_argument("target", help="URL ou domínio alvo (ex: https://exemplo.com)")

    # ── inventory ─────────────────────────────────────────────────────────
    inv = subparsers.add_parser("inventory", help="Descobre hosts ativos na rede local")
    inv.add_argument("network", help="Rede CIDR alvo (ex: 192.168.1.0/24)")

    # ── log-analyze ───────────────────────────────────────────────────────
    la = subparsers.add_parser("log-analyze", help="Analisa arquivos de log em busca de ameaças")
    la.add_argument("logfile", help="Caminho para o arquivo de log")
    la.add_argument("--type", choices=["auth", "apache", "generic"], default="auth",
                    help="Tipo de log. Padrão: auth")

    # ── full-audit ────────────────────────────────────────────────────────
    fa = subparsers.add_parser("full-audit", help="Executa auditoria completa e gera relatório HTML")
    fa.add_argument("target", help="IP ou hostname alvo")
    fa.add_argument("--network", help="Rede CIDR (ex: 192.168.1.0/24)")
    fa.add_argument("--logfile", help="Arquivo de log para análise")
    fa.add_argument("--output", default="reports/audit_report.html",
                    help="Caminho do relatório de saída")

    return parser.parse_args()


def run_port_scan(args):
    print(f"\n[*] Iniciando Port Scan em: {args.target}")
    scanner = PortScanner(target=args.target, port_range=args.ports, timeout=args.timeout)
    results = scanner.scan()
    scanner.print_results(results)
    return results


def run_header_check(args):
    print(f"\n[*] Verificando headers HTTP de: {args.target}")
    checker = HeaderChecker(target=args.target)
    results = checker.check()
    checker.print_results(results)
    return results


def run_inventory(args):
    print(f"\n[*] Mapeando hosts na rede: {args.network}")
    inventory = NetworkInventory(network=args.network)
    results = inventory.scan()
    inventory.print_results(results)
    return results


def run_log_analyze(args):
    print(f"\n[*] Analisando log: {args.logfile}")
    analyzer = LogAnalyzer(logfile=args.logfile, log_type=args.type)
    results = analyzer.analyze()
    analyzer.print_results(results)
    return results


def main():
    print(BANNER)
    args = parse_args()

    if not args.command:
        print("  Use --help para ver os módulos disponíveis.\n")
        sys.exit(0)

    os.makedirs("reports", exist_ok=True)

    if args.command == "port-scan":
        run_port_scan(args)

    elif args.command == "header-check":
        run_header_check(args)

    elif args.command == "inventory":
        run_inventory(args)

    elif args.command == "log-analyze":
        run_log_analyze(args)

    elif args.command == "full-audit":
        print(f"\n{'='*55}")
        print(f"  AUDITORIA COMPLETA — {args.target}")
        print(f"  {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}")
        print(f"{'='*55}")

        all_results = {}

        # Port Scan
        class PsArgs:
            target = args.target
            ports = "1-1024"
            timeout = 0.5
        all_results["port_scan"] = run_port_scan(PsArgs())

        # Header Check
        url = args.target if args.target.startswith("http") else f"http://{args.target}"
        class HcArgs:
            target = url
        all_results["header_check"] = run_header_check(HcArgs())

        # Inventory
        if args.network:
            class InvArgs:
                network = args.network
            all_results["inventory"] = run_inventory(InvArgs())

        # Log Analysis
        if args.logfile:
            class LaArgs:
                logfile = args.logfile
                type = "auth"
            all_results["log_analysis"] = run_log_analyze(LaArgs())

        # Report
        print(f"\n[*] Gerando relatório HTML em: {args.output}")
        reporter = ReportGenerator(target=args.target, results=all_results)
        reporter.generate(output_path=args.output)
        print(f"[+] Relatório salvo em: {args.output}\n")


if __name__ == "__main__":
    main()
