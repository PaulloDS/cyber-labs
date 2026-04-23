"""
Módulo 5 — Report Generator
=============================
Consolida os resultados de todos os módulos em um
relatório HTML profissional com severidade codificada por cor.
"""

from datetime import datetime
from pathlib import Path


SEVERITY_BADGE = {
    "HIGH":   '<span class="badge high">HIGH</span>',
    "MEDIUM": '<span class="badge medium">MEDIUM</span>',
    "LOW":    '<span class="badge low">LOW</span>',
    "INFO":   '<span class="badge info">INFO</span>',
}

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>NetGuard — Relatório de Auditoria</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #c9d1d9; line-height: 1.6; }}
    header {{ background: linear-gradient(135deg, #1b3a6b, #2e5fa3); padding: 32px 40px; }}
    header h1 {{ font-size: 28px; color: #fff; letter-spacing: 1px; }}
    header p {{ color: #a8c4e8; margin-top: 4px; font-size: 14px; }}
    .meta {{ display: flex; gap: 24px; margin-top: 16px; flex-wrap: wrap; }}
    .meta span {{ background: rgba(255,255,255,0.1); padding: 4px 12px; border-radius: 20px;
                  font-size: 13px; color: #fff; }}
    .container {{ max-width: 1100px; margin: 32px auto; padding: 0 24px; }}
    .summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 32px; }}
    .summary-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
                     padding: 20px; text-align: center; }}
    .summary-card .num {{ font-size: 36px; font-weight: bold; }}
    .summary-card .label {{ font-size: 13px; color: #8b949e; margin-top: 4px; }}
    .num.high {{ color: #f85149; }}
    .num.medium {{ color: #e3b341; }}
    .num.low {{ color: #3fb950; }}
    .num.info {{ color: #58a6ff; }}
    .section {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px;
                margin-bottom: 24px; overflow: hidden; }}
    .section-header {{ background: #1c2128; padding: 16px 24px; border-bottom: 1px solid #30363d;
                       display: flex; align-items: center; gap: 12px; }}
    .section-header h2 {{ font-size: 16px; color: #e6edf3; }}
    .section-header .module-icon {{ font-size: 20px; }}
    .section-body {{ padding: 20px 24px; }}
    table {{ width: 100%; border-collapse: collapse; font-size: 14px; }}
    th {{ text-align: left; padding: 10px 12px; background: #1c2128; color: #8b949e;
          font-weight: 600; font-size: 12px; text-transform: uppercase; border-bottom: 1px solid #30363d; }}
    td {{ padding: 10px 12px; border-bottom: 1px solid #21262d; vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: #1c2128; }}
    .badge {{ display: inline-block; padding: 2px 10px; border-radius: 12px; font-size: 12px;
              font-weight: 700; letter-spacing: 0.5px; }}
    .badge.high {{ background: #3d1a1a; color: #f85149; border: 1px solid #f85149; }}
    .badge.medium {{ background: #2d2a1a; color: #e3b341; border: 1px solid #e3b341; }}
    .badge.low {{ background: #1a2d1a; color: #3fb950; border: 1px solid #3fb950; }}
    .badge.info {{ background: #1a2240; color: #58a6ff; border: 1px solid #58a6ff; }}
    .ok {{ color: #3fb950; }}
    .warn {{ color: #e3b341; }}
    .fail {{ color: #f85149; }}
    .stat-row {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 16px; }}
    .stat {{ background: #1c2128; border-radius: 6px; padding: 8px 16px; font-size: 13px; }}
    .stat strong {{ color: #e6edf3; }}
    code {{ background: #1c2128; padding: 2px 6px; border-radius: 4px; font-size: 12px;
            color: #79c0ff; font-family: monospace; }}
    footer {{ text-align: center; padding: 32px; color: #484f58; font-size: 13px; }}
    .empty {{ color: #484f58; font-style: italic; text-align: center; padding: 20px; }}
    .grade {{ font-size: 48px; font-weight: bold; }}
    .grade-A, .grade-B {{ color: #3fb950; }}
    .grade-C {{ color: #e3b341; }}
    .grade-D, .grade-F {{ color: #f85149; }}
  </style>
</head>
<body>
  <header>
    <h1>🔐 NetGuard — Relatório de Auditoria de Segurança</h1>
    <p>Análise automatizada de segurança de rede e infraestrutura</p>
    <div class="meta">
      <span>🎯 Alvo: {target}</span>
      <span>📅 {date}</span>
      <span>🛠 NetGuard v1.0</span>
    </div>
  </header>

  <div class="container">
    {summary}
    {port_scan_section}
    {header_check_section}
    {inventory_section}
    {log_section}
  </div>

  <footer>
    Gerado por NetGuard — Network Security Audit Toolkit &bull;
    <a href="https://github.com/seuperfil/netguard" style="color:#58a6ff">github.com/seuperfil/netguard</a>
  </footer>
</body>
</html>"""


class ReportGenerator:
    def __init__(self, target: str, results: dict):
        self.target = target
        self.results = results

    def generate(self, output_path: str = "reports/audit_report.html"):
        Path(output_path).parent.mkdir(parents=True, exist_ok=True)

        html = HTML_TEMPLATE.format(
            target=self.target,
            date=datetime.now().strftime("%d/%m/%Y às %H:%M:%S"),
            summary=self._build_summary(),
            port_scan_section=self._build_port_scan(),
            header_check_section=self._build_header_check(),
            inventory_section=self._build_inventory(),
            log_section=self._build_log_analysis(),
        )

        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)

    def _build_summary(self) -> str:
        all_findings = []
        for module_result in self.results.values():
            if isinstance(module_result, dict):
                all_findings.extend(module_result.get("findings", []))

        counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in all_findings:
            sev = f.get("severity", "INFO")
            counts[sev] = counts.get(sev, 0) + 1

        total = sum(counts.values())
        risk = "Crítico" if counts["HIGH"] > 0 else ("Moderado" if counts["MEDIUM"] > 0 else "Baixo")
        risk_color = "high" if counts["HIGH"] > 0 else ("medium" if counts["MEDIUM"] > 0 else "low")

        return f"""
    <div class="summary-grid">
      <div class="summary-card">
        <div class="num {risk_color}">{risk}</div>
        <div class="label">Risco Geral</div>
      </div>
      <div class="summary-card">
        <div class="num">{total}</div>
        <div class="label">Total de Achados</div>
      </div>
      <div class="summary-card">
        <div class="num high">{counts['HIGH']}</div>
        <div class="label">Severidade Alta</div>
      </div>
      <div class="summary-card">
        <div class="num medium">{counts['MEDIUM']}</div>
        <div class="label">Severidade Média</div>
      </div>
      <div class="summary-card">
        <div class="num low">{counts['LOW']}</div>
        <div class="label">Severidade Baixa</div>
      </div>
      <div class="summary-card">
        <div class="num info">{counts['INFO']}</div>
        <div class="label">Informacional</div>
      </div>
    </div>"""

    def _build_port_scan(self) -> str:
        r = self.results.get("port_scan")
        if not r:
            return ""

        rows = ""
        for f in r.get("findings", []):
            badge = SEVERITY_BADGE.get(f["severity"], f["severity"])
            rows += f"""
        <tr>
          <td><code>{f['port']}</code></td>
          <td>{f['service']}</td>
          <td>{badge}</td>
          <td>{f['note']}</td>
        </tr>"""

        if not rows:
            rows = '<tr><td colspan="4" class="empty">Nenhuma porta aberta encontrada.</td></tr>'

        return f"""
    <div class="section">
      <div class="section-header">
        <span class="module-icon">🔍</span>
        <h2>Port Scanner</h2>
      </div>
      <div class="section-body">
        <div class="stat-row">
          <div class="stat">Alvo: <strong>{r['target']} ({r['ip']})</strong></div>
          <div class="stat">Portas verificadas: <strong>{r['ports_scanned']}</strong></div>
          <div class="stat">Portas abertas: <strong>{r['open_ports']}</strong></div>
          <div class="stat">Tempo: <strong>{r['elapsed']}s</strong></div>
        </div>
        <table>
          <thead><tr><th>Porta</th><th>Serviço</th><th>Severidade</th><th>Observação</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </div>"""

    def _build_header_check(self) -> str:
        r = self.results.get("header_check")
        if not r:
            return ""

        grade = r.get("grade", "?")
        rows = ""
        for f in r.get("findings", []):
            badge = SEVERITY_BADGE.get(f["severity"], f["severity"])
            status_icon = "✓" if f["status"] == "PRESENT_VALID" else ("⚠" if f["status"] == "PRESENT_INVALID" else "✗")
            rows += f"""
        <tr>
          <td><code>{f['header']}</code></td>
          <td>{badge}</td>
          <td>{status_icon} {f['note'][:80]}</td>
        </tr>"""

        leaked_rows = ""
        for lh in r.get("leaked_headers", []):
            leaked_rows += f"""
        <tr>
          <td><code>{lh['header']}</code></td>
          <td>{SEVERITY_BADGE['MEDIUM']}</td>
          <td>⚠ Valor exposto: <code>{lh['value'][:40]}</code> — {lh['risk']}</td>
        </tr>"""

        https_status = '<span class="ok">✓ Ativo</span>' if r.get("uses_https") else '<span class="fail">✗ Inativo — tráfego não criptografado</span>'

        return f"""
    <div class="section">
      <div class="section-header">
        <span class="module-icon">🌐</span>
        <h2>HTTP Security Headers</h2>
      </div>
      <div class="section-body">
        <div class="stat-row">
          <div class="stat">Alvo: <strong>{r['target']}</strong></div>
          <div class="stat">HTTPS: {https_status}</div>
          <div class="stat">Score: <strong>{r['score']}/{r['max_score']}</strong></div>
          <div class="stat">Nota: <strong class="grade grade-{grade}">{grade}</strong></div>
        </div>
        <table>
          <thead><tr><th>Header</th><th>Severidade</th><th>Status / Observação</th></tr></thead>
          <tbody>{rows}{leaked_rows}</tbody>
        </table>
      </div>
    </div>"""

    def _build_inventory(self) -> str:
        r = self.results.get("inventory")
        if not r:
            return ""

        rows = ""
        for host in r.get("inventory", []):
            services = ", ".join(f"<code>{s}</code>" for s in host["services"]) if host["services"] else "—"
            rows += f"""
        <tr>
          <td><code>{host['ip']}</code></td>
          <td>{host['hostname']}</td>
          <td>{host['device_type']}</td>
          <td>{services}</td>
        </tr>"""

        if not rows:
            rows = '<tr><td colspan="4" class="empty">Nenhum host ativo encontrado.</td></tr>'

        return f"""
    <div class="section">
      <div class="section-header">
        <span class="module-icon">🗺</span>
        <h2>Network Inventory</h2>
      </div>
      <div class="section-body">
        <div class="stat-row">
          <div class="stat">Rede: <strong>{r['network']}</strong></div>
          <div class="stat">Hosts ativos: <strong>{r['active_hosts']}</strong></div>
          <div class="stat">Total verificado: <strong>{r['total_hosts']}</strong></div>
        </div>
        <table>
          <thead><tr><th>IP</th><th>Hostname</th><th>Tipo</th><th>Serviços Detectados</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
      </div>
    </div>"""

    def _build_log_analysis(self) -> str:
        r = self.results.get("log_analysis")
        if not r:
            return ""

        findings = r.get("findings", [])
        rows = ""
        for f in findings:
            badge = SEVERITY_BADGE.get(f["severity"], f["severity"])
            rows += f"""
        <tr>
          <td>{f['type']}</td>
          <td>{badge}</td>
          <td>{f['detail']}</td>
        </tr>"""

        if not rows:
            rows = '<tr><td colspan="3" class="empty">Nenhum padrão suspeito detectado.</td></tr>'

        extra = ""
        if r.get("brute_force_ips"):
            bf_rows = "".join(
                f"<tr><td><code>{ip}</code></td><td>{count} tentativas</td></tr>"
                for ip, count in sorted(r["brute_force_ips"].items(), key=lambda x: -x[1])
            )
            extra = f"""
        <h3 style="margin: 16px 0 8px; color:#f85149; font-size:14px;">IPs com Brute Force Detectado</h3>
        <table>
          <thead><tr><th>IP</th><th>Tentativas Falhas</th></tr></thead>
          <tbody>{bf_rows}</tbody>
        </table>"""

        return f"""
    <div class="section">
      <div class="section-header">
        <span class="module-icon">📋</span>
        <h2>Log Analyzer</h2>
      </div>
      <div class="section-body">
        <div class="stat-row">
          <div class="stat">Arquivo: <strong>{Path(r['logfile']).name}</strong></div>
          <div class="stat">Linhas analisadas: <strong>{r['total_lines']:,}</strong></div>
          {'<div class="stat">Logins falhos: <strong class="fail">' + str(r.get('total_failed_logins', 0)) + '</strong></div>' if r.get('total_failed_logins') is not None else ''}
          {'<div class="stat">Logins ok: <strong class="ok">' + str(r.get('total_success_logins', 0)) + '</strong></div>' if r.get('total_success_logins') is not None else ''}
        </div>
        <table>
          <thead><tr><th>Tipo de Achado</th><th>Severidade</th><th>Detalhe</th></tr></thead>
          <tbody>{rows}</tbody>
        </table>
        {extra}
      </div>
    </div>"""
