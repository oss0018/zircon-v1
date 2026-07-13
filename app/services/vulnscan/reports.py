"""Report generation for the Vulnerability Scanner.

Turns a completed scan's findings into a downloadable report in one of
several formats. Every generator takes the same (scan, target, findings)
triple and returns raw bytes so callers can persist or stream them without
caring about the specific format.
"""
import csv
import html
import io
import json
from datetime import datetime, timezone

from app.models import VSFinding, VSScan, VSScanTarget

VALID_REPORT_FORMATS = {"json", "csv", "html", "kql", "pdf"}

_REPORT_MIME_TYPES = {
    "json": "application/json",
    "csv": "text/csv",
    "html": "text/html",
    "kql": "text/plain",
    "pdf": "application/pdf",
}

_SEVERITY_COLORS = {
    "CRITICAL": "#ff003c",
    "HIGH": "#ffb300",
    "MEDIUM": "#eab308",
    "LOW": "#00b4d8",
    "INFO": "#94a3b8",
}


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value) -> str:
    return value.isoformat() if value else ""


def _cve_ids(finding: VSFinding) -> list[str]:
    try:
        return json.loads(finding.cve_ids_json or "[]")
    except (TypeError, ValueError):
        return []


def _severity_counts(findings: list[VSFinding]) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def _finding_dict(finding: VSFinding) -> dict:
    return {
        "id": finding.id,
        "title": finding.title,
        "description": finding.description,
        "severity": finding.severity,
        "finding_type": finding.finding_type,
        "scanner_source": finding.scanner_source,
        "status": finding.status,
        "target_url": finding.target_url,
        "target_host": finding.target_host,
        "target_port": finding.target_port,
        "cve_ids": _cve_ids(finding),
        "remediation_summary": finding.remediation_summary,
        "first_seen": _iso(finding.first_seen),
        "last_seen": _iso(finding.last_seen),
    }


def generate_json(scan: VSScan, target: VSScanTarget, findings: list[VSFinding]) -> bytes:
    payload = {
        "scan": {
            "id": scan.id,
            "profile": scan.profile,
            "status": scan.status,
            "overall_risk": scan.overall_risk,
            "findings_total": scan.findings_total,
            "findings_critical": scan.findings_critical,
            "findings_high": scan.findings_high,
            "findings_medium": scan.findings_medium,
            "findings_low": scan.findings_low,
            "findings_info": scan.findings_info,
            "findings_new": scan.findings_new,
            "findings_fixed": scan.findings_fixed,
            "started_at": _iso(scan.started_at),
            "completed_at": _iso(scan.completed_at),
        },
        "target": {
            "id": target.id,
            "name": target.name,
            "target_type": target.target_type,
            "target_value": target.target_value,
        },
        "findings": [_finding_dict(f) for f in findings],
        "generated_at": _iso(_utcnow()),
    }
    return json.dumps(payload, indent=2).encode("utf-8")


def generate_csv(scan: VSScan, target: VSScanTarget, findings: list[VSFinding]) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "ID", "Severity", "Type", "Title", "Scanner", "Status",
            "Target Host", "Target Port", "CVE IDs", "First Seen", "Last Seen",
        ]
    )
    for finding in findings:
        writer.writerow(
            [
                finding.id,
                finding.severity,
                finding.finding_type,
                finding.title,
                finding.scanner_source,
                finding.status,
                finding.target_host,
                finding.target_port or "",
                ",".join(_cve_ids(finding)),
                _iso(finding.first_seen),
                _iso(finding.last_seen),
            ]
        )
    return output.getvalue().encode("utf-8")


def generate_html(scan: VSScan, target: VSScanTarget, findings: list[VSFinding]) -> bytes:
    counts = _severity_counts(findings)
    rows = "\n".join(
        "<tr>"
        f"<td><span style=\"color:{_SEVERITY_COLORS.get(f.severity, '#94a3b8')};font-weight:600;\">{html.escape(f.severity)}</span></td>"
        f"<td>{html.escape(f.title)}</td>"
        f"<td>{html.escape(f.finding_type)}</td>"
        f"<td>{html.escape(f.scanner_source)}</td>"
        f"<td>{html.escape(f.target_host)}{(':' + str(f.target_port)) if f.target_port else ''}</td>"
        f"<td>{html.escape(f.status)}</td>"
        "</tr>"
        for f in findings
    ) or "<tr><td colspan=\"6\">No findings recorded for this scan.</td></tr>"

    stat_cards = "".join(
        f"<div class=\"stat\"><div class=\"stat-value\" style=\"color:{_SEVERITY_COLORS[sev]};\">{count}</div>"
        f"<div class=\"stat-label\">{sev.title()}</div></div>"
        for sev, count in counts.items()
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Zircon Vulnerability Scan Report #{scan.id}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Arial, sans-serif; margin: 32px; color: #111827; }}
  h1 {{ margin-bottom: 4px; }}
  .meta {{ color: #475569; margin-bottom: 24px; }}
  .stats {{ display: flex; gap: 16px; margin-bottom: 24px; }}
  .stat {{ border: 1px solid #e2e8f0; border-radius: 8px; padding: 12px 20px; text-align: center; }}
  .stat-value {{ font-size: 24px; font-weight: 700; }}
  .stat-label {{ font-size: 12px; color: #475569; text-transform: uppercase; }}
  table {{ border-collapse: collapse; width: 100%; }}
  th, td {{ border: 1px solid #e2e8f0; padding: 8px 10px; text-align: left; font-size: 13px; }}
  th {{ background: #f8fafc; }}
</style>
</head>
<body>
  <h1>Vulnerability Scan Report</h1>
  <div class="meta">
    Target: <b>{html.escape(target.name)}</b> ({html.escape(target.target_value)})<br>
    Scan #{scan.id} &middot; Profile: {html.escape(scan.profile)} &middot; Overall risk: {html.escape(scan.overall_risk or 'N/A')}<br>
    Completed: {html.escape(_iso(scan.completed_at) or 'N/A')} &middot; Generated: {html.escape(_iso(_utcnow()))}
  </div>
  <div class="stats">{stat_cards}</div>
  <table>
    <thead><tr><th>Severity</th><th>Title</th><th>Type</th><th>Scanner</th><th>Target</th><th>Status</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
</body>
</html>
""".encode("utf-8")


def _kql_escape(value: str) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


def generate_kql(scan: VSScan, target: VSScanTarget, findings: list[VSFinding]) -> bytes:
    """Emit a Kusto `datatable` literal so findings can be pasted straight into
    a Log Analytics / Microsoft Sentinel query window for further triage,
    without needing a live data connector.
    """
    lines = [
        "// Zircon Vulnerability Scan export - paste into a Log Analytics / Sentinel query window",
        f"// Scan #{scan.id} for target '{_kql_escape(target.name)}' ({_kql_escape(target.target_value)})",
        f"// Generated {_iso(_utcnow())}",
        "let ZirconFindings = datatable(FindingId:int, Severity:string, FindingType:string, Title:string, "
        "Scanner:string, TargetHost:string, TargetPort:int, Status:string, CveIds:string)",
        "[",
    ]
    row_strings = [
        "    {0}, \"{1}\", \"{2}\", \"{3}\", \"{4}\", \"{5}\", {6}, \"{7}\", \"{8}\"".format(
            f.id,
            _kql_escape(f.severity),
            _kql_escape(f.finding_type),
            _kql_escape(f.title),
            _kql_escape(f.scanner_source),
            _kql_escape(f.target_host),
            f.target_port or 0,
            _kql_escape(f.status),
            _kql_escape(",".join(_cve_ids(f))),
        )
        for f in findings
    ]
    lines.append(",\n".join(row_strings) if row_strings else '    0, "INFO", "NONE", "No findings", "none", "", 0, "new", ""')
    lines.append("];")
    lines.append("ZirconFindings | order by Severity asc")
    return "\n".join(lines).encode("utf-8")


def generate_pdf(scan: VSScan, target: VSScanTarget, findings: list[VSFinding]) -> bytes:
    import fitz  # PyMuPDF; already a project dependency, used here to build (not just parse) PDFs

    counts = _severity_counts(findings)
    doc = fitz.open()
    page = doc.new_page()
    margin = 54
    y = margin

    def write_line(text: str, size: float = 11, dy: float = 16, color=(0.07, 0.09, 0.15)):
        nonlocal y, page
        if y > page.rect.height - margin:
            page = doc.new_page()
            y = margin
        page.insert_text((margin, y), text, fontsize=size, color=color)
        y += dy

    write_line("Zircon Vulnerability Scan Report", size=18, dy=26)
    write_line(f"Target: {target.name} ({target.target_value})", size=11)
    write_line(f"Scan #{scan.id}  Profile: {scan.profile}  Overall risk: {scan.overall_risk or 'N/A'}", size=11)
    write_line(f"Completed: {_iso(scan.completed_at) or 'N/A'}  Generated: {_iso(_utcnow())}", size=11, dy=22)

    write_line(
        "Critical: {0}   High: {1}   Medium: {2}   Low: {3}   Info: {4}".format(
            counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"], counts["INFO"]
        ),
        size=12,
        dy=24,
    )

    if not findings:
        write_line("No findings recorded for this scan.", size=11)
    for finding in findings:
        write_line(f"[{finding.severity}] {finding.title}", size=12, dy=15)
        target_desc = finding.target_host + (f":{finding.target_port}" if finding.target_port else "")
        write_line(f"    {finding.finding_type} via {finding.scanner_source} on {target_desc}", size=9, color=(0.3, 0.35, 0.45))

    buf = io.BytesIO()
    doc.save(buf)
    doc.close()
    return buf.getvalue()


_GENERATORS = {
    "json": generate_json,
    "csv": generate_csv,
    "html": generate_html,
    "kql": generate_kql,
    "pdf": generate_pdf,
}


def generate_report(fmt: str, scan: VSScan, target: VSScanTarget, findings: list[VSFinding]) -> tuple[bytes, str, str]:
    """Generate a report and return (content_bytes, file_extension, mime_type)."""
    generator = _GENERATORS.get(fmt)
    if generator is None:
        raise ValueError(f"Unsupported report format: {fmt}")
    content = generator(scan, target, findings)
    return content, fmt, _REPORT_MIME_TYPES[fmt]
