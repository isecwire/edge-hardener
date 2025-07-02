#!/usr/bin/env python3
"""
edge-hardener — Report generator (HTML, JSON summary, text)
Copyright (c) 2026 isecwire GmbH. MIT License.

Reads JSON output from edge_hardener.sh and generates a standalone HTML report
with executive summary, risk scoring, per-category breakdown, radar chart,
remediation priority list, and CIS/IEC 62443 compliance percentage.

Usage:
    ./edge_hardener.sh -j results.json
    python3 generate_report.py results.json -o report.html
    python3 generate_report.py results.json --format text
    python3 generate_report.py results.json --baseline previous.json -o report.html
"""

import argparse
import html
import json
import math
import sys
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Risk score calculation
# ---------------------------------------------------------------------------

def compute_risk_score(data: dict) -> int:
    """Compute a risk score from 0 (secure) to 100 (critical)."""
    summary = data.get("summary", {})
    total = summary.get("total", 0)
    if total == 0:
        return 0
    fail = summary.get("fail", 0)
    warn = summary.get("warn", 0)
    score = int((fail * 10 + warn * 3) * 100 / (total * 10))
    return min(score, 100)


def risk_label(score: int) -> str:
    if score <= 10:
        return "Excellent"
    if score <= 25:
        return "Good"
    if score <= 50:
        return "Moderate"
    if score <= 75:
        return "High"
    return "Critical"


def risk_color(score: int) -> str:
    if score <= 10:
        return "#22c55e"
    if score <= 25:
        return "#86efac"
    if score <= 50:
        return "#f59e0b"
    if score <= 75:
        return "#ef4444"
    return "#dc2626"


# ---------------------------------------------------------------------------
# Category analysis
# ---------------------------------------------------------------------------

def analyze_categories(results: list) -> dict:
    """Group results by category and compute per-category stats."""
    cats = defaultdict(lambda: {"pass": 0, "fail": 0, "warn": 0, "total": 0})
    for r in results:
        cat = r.get("category", "Uncategorized")
        status = r.get("status", "WARN")
        cats[cat]["total"] += 1
        cats[cat][status.lower()] += 1
    return dict(cats)


def compliance_percentage(data: dict) -> float:
    """Percentage of checks that passed (CIS/IEC 62443 proxy)."""
    summary = data.get("summary", {})
    total = summary.get("total", 0)
    if total == 0:
        return 100.0
    return round(summary.get("pass", 0) / total * 100, 1)


# ---------------------------------------------------------------------------
# ASCII radar chart (for text output)
# ---------------------------------------------------------------------------

def ascii_radar_chart(categories: dict, width: int = 60) -> str:
    """Generate a simple ASCII bar chart showing per-category pass rate."""
    lines = []
    lines.append("  Per-Category Pass Rate")
    lines.append("  " + "-" * width)
    for cat, stats in sorted(categories.items()):
        total = stats["total"]
        if total == 0:
            pct = 100
        else:
            pct = int(stats["pass"] / total * 100)
        bar_len = int(pct * (width - 30) / 100)
        bar = "#" * bar_len + "." * ((width - 30) - bar_len)
        name = cat[:20].ljust(20)
        lines.append(f"  {name} [{bar}] {pct:3d}%")
    lines.append("  " + "-" * width)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Remediation priority list
# ---------------------------------------------------------------------------

def remediation_priority(results: list) -> list:
    """Sort results by severity for remediation prioritization."""
    actionable = [r for r in results if r.get("remediation") and r.get("status") in ("FAIL", "WARN")]
    severity_order = {"FAIL": 0, "WARN": 1}
    return sorted(actionable, key=lambda r: severity_order.get(r.get("status", "WARN"), 1))


# ---------------------------------------------------------------------------
# Baseline comparison
# ---------------------------------------------------------------------------

def compare_baselines(current: dict, baseline: dict) -> dict:
    """Compare current and baseline results."""
    b_checks = {r["check"]: r["status"] for r in baseline.get("results", [])}
    c_checks = {r["check"]: r["status"] for r in current.get("results", [])}

    regressions = []
    improved = []
    new_findings = []
    removed = []

    for check, status in c_checks.items():
        if check not in b_checks:
            new_findings.append({"check": check, "status": status})
        elif b_checks[check] == "PASS" and status in ("FAIL", "WARN"):
            regressions.append({"check": check, "was": b_checks[check], "now": status})
        elif b_checks[check] in ("FAIL", "WARN") and status == "PASS":
            improved.append({"check": check, "was": b_checks[check], "now": status})

    for check, status in b_checks.items():
        if check not in c_checks:
            removed.append({"check": check, "status": status})

    return {
        "regressions": regressions,
        "improved": improved,
        "new_findings": new_findings,
        "removed": removed,
        "baseline_timestamp": baseline.get("timestamp", "unknown"),
    }


# ---------------------------------------------------------------------------
# HTML template
# ---------------------------------------------------------------------------

HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>edge-hardener Report — {hostname}</title>
<style>
  :root {{
    --pass: #22c55e;
    --fail: #ef4444;
    --warn: #f59e0b;
    --bg:   #0f172a;
    --card: #1e293b;
    --text: #e2e8f0;
    --muted:#94a3b8;
    --border:#334155;
    --risk-color: {risk_color};
  }}
  * {{ margin: 0; padding: 0; box-sizing: border-box; }}
  body {{
    font-family: "Inter", "Segoe UI", system-ui, -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 2rem;
  }}
  .container {{ max-width: 1024px; margin: 0 auto; }}
  header {{
    border-bottom: 1px solid var(--border);
    padding-bottom: 1.5rem;
    margin-bottom: 2rem;
  }}
  header h1 {{
    font-size: 1.75rem;
    font-weight: 700;
    letter-spacing: -0.02em;
  }}
  header h1 span {{ color: var(--muted); font-weight: 400; }}
  .meta {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 0.5rem;
    margin-top: 0.75rem;
    font-size: 0.875rem;
    color: var(--muted);
  }}
  .meta strong {{ color: var(--text); }}

  /* Executive summary */
  .executive {{
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1.5rem;
    margin-bottom: 2rem;
  }}
  .executive h2 {{
    font-size: 1.1rem;
    margin-bottom: 1rem;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
    font-weight: 600;
  }}
  .risk-score {{
    display: flex;
    align-items: center;
    gap: 1.5rem;
    margin-bottom: 1rem;
  }}
  .risk-circle {{
    width: 80px;
    height: 80px;
    border-radius: 50%;
    border: 4px solid var(--risk-color);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-direction: column;
  }}
  .risk-circle .score {{
    font-size: 1.75rem;
    font-weight: 700;
    color: var(--risk-color);
    line-height: 1;
  }}
  .risk-circle .label {{
    font-size: 0.6rem;
    color: var(--muted);
    text-transform: uppercase;
  }}
  .risk-detail {{ font-size: 0.9rem; }}
  .risk-detail .risk-label {{ color: var(--risk-color); font-weight: 700; }}
  .compliance {{
    display: flex;
    gap: 2rem;
    margin-top: 0.75rem;
    font-size: 0.85rem;
  }}
  .compliance div {{ padding: 0.5rem 1rem; background: rgba(255,255,255,0.03); border-radius: 6px; }}

  /* Summary cards */
  .summary {{
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 1rem;
    margin-bottom: 2rem;
  }}
  .summary-card {{
    background: var(--card);
    border-radius: 8px;
    padding: 1.25rem;
    text-align: center;
    border: 1px solid var(--border);
  }}
  .summary-card .number {{
    font-size: 2.25rem;
    font-weight: 700;
    line-height: 1;
  }}
  .summary-card .label {{
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
    margin-top: 0.25rem;
  }}
  .summary-card.pass .number {{ color: var(--pass); }}
  .summary-card.fail .number {{ color: var(--fail); }}
  .summary-card.warn .number {{ color: var(--warn); }}
  .summary-card.total .number {{ color: var(--text); }}

  /* Category breakdown */
  .categories {{
    margin-bottom: 2rem;
  }}
  .categories h2 {{
    font-size: 1rem;
    margin-bottom: 1rem;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  .cat-row {{
    display: grid;
    grid-template-columns: 200px 1fr 60px;
    gap: 1rem;
    padding: 0.5rem 0;
    align-items: center;
    border-bottom: 1px solid rgba(255,255,255,0.04);
    font-size: 0.85rem;
  }}
  .cat-bar {{
    height: 8px;
    border-radius: 4px;
    background: rgba(255,255,255,0.06);
    overflow: hidden;
    display: flex;
  }}
  .cat-bar .pass-seg {{ background: var(--pass); }}
  .cat-bar .warn-seg {{ background: var(--warn); }}
  .cat-bar .fail-seg {{ background: var(--fail); }}

  /* Remediation priority */
  .remediation-list {{
    margin-bottom: 2rem;
  }}
  .remediation-list h2 {{
    font-size: 1rem;
    margin-bottom: 1rem;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  .rem-item {{
    padding: 0.75rem 1rem;
    border-left: 3px solid var(--warn);
    background: rgba(255,255,255,0.02);
    margin-bottom: 0.5rem;
    border-radius: 0 6px 6px 0;
    font-size: 0.85rem;
  }}
  .rem-item.fail {{ border-left-color: var(--fail); }}
  .rem-item .rem-check {{ font-weight: 600; }}
  .rem-item .rem-action {{ color: var(--muted); margin-top: 0.2rem; }}
  .rem-item .rem-cis {{ font-size: 0.75rem; color: var(--muted); }}

  /* Baseline comparison */
  .baseline {{
    margin-bottom: 2rem;
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 1.5rem;
  }}
  .baseline h2 {{
    font-size: 1rem;
    margin-bottom: 1rem;
    color: var(--muted);
    text-transform: uppercase;
    letter-spacing: 0.05em;
  }}
  .baseline .regression {{ color: var(--fail); }}
  .baseline .improved {{ color: var(--pass); }}
  .baseline .new-finding {{ color: var(--warn); }}

  /* Results table */
  .results {{ margin-bottom: 2rem; }}
  .result-row {{
    display: grid;
    grid-template-columns: 72px 1fr;
    gap: 1rem;
    padding: 0.875rem 1rem;
    border-bottom: 1px solid var(--border);
    align-items: start;
  }}
  .result-row:hover {{ background: rgba(255,255,255,0.02); }}
  .badge {{
    display: inline-block;
    padding: 0.2rem 0.6rem;
    border-radius: 4px;
    font-size: 0.75rem;
    font-weight: 700;
    text-transform: uppercase;
    text-align: center;
    min-width: 56px;
  }}
  .badge.pass {{ background: rgba(34,197,94,0.15); color: var(--pass); }}
  .badge.fail {{ background: rgba(239,68,68,0.15); color: var(--fail); }}
  .badge.warn {{ background: rgba(245,158,11,0.15); color: var(--warn); }}
  .check-name {{ font-weight: 600; }}
  .check-detail {{ font-size: 0.875rem; color: var(--muted); margin-top: 0.15rem; }}
  .check-cis {{ font-size: 0.75rem; color: var(--muted); opacity: 0.7; }}
  .remediation {{
    margin-top: 0.4rem;
    padding: 0.5rem 0.75rem;
    background: rgba(245,158,11,0.08);
    border-left: 3px solid var(--warn);
    border-radius: 0 4px 4px 0;
    font-size: 0.8rem;
    color: var(--warn);
  }}
  .remediation.fail-rem {{
    background: rgba(239,68,68,0.08);
    border-left-color: var(--fail);
    color: var(--fail);
  }}
  .policy-violation {{
    margin-top: 0.3rem;
    font-size: 0.75rem;
    color: #c084fc;
    font-style: italic;
  }}

  /* Filter buttons */
  .filters {{
    display: flex;
    gap: 0.5rem;
    margin-bottom: 1rem;
  }}
  .filters button {{
    padding: 0.4rem 1rem;
    border-radius: 6px;
    border: 1px solid var(--border);
    background: var(--card);
    color: var(--text);
    cursor: pointer;
    font-size: 0.8rem;
    transition: 0.15s;
  }}
  .filters button:hover {{ border-color: var(--text); }}
  .filters button.active {{ border-color: var(--pass); color: var(--pass); }}

  footer {{
    text-align: center;
    padding-top: 2rem;
    font-size: 0.75rem;
    color: var(--muted);
    border-top: 1px solid var(--border);
  }}

  @media (max-width: 640px) {{
    .summary {{ grid-template-columns: repeat(2, 1fr); }}
    body {{ padding: 1rem; }}
    .cat-row {{ grid-template-columns: 1fr; }}
  }}
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>edge-hardener <span>Security Audit Report</span></h1>
    <div class="meta">
      <div><strong>Host:</strong> {hostname}</div>
      <div><strong>Kernel:</strong> {kernel}</div>
      <div><strong>Arch:</strong> {arch}</div>
      <div><strong>Scanned:</strong> {timestamp}</div>
      {policy_meta}
    </div>
  </header>

  <!-- Executive Summary -->
  <div class="executive">
    <h2>Executive Summary</h2>
    <div class="risk-score">
      <div class="risk-circle">
        <div class="score">{risk_score}</div>
        <div class="label">Risk</div>
      </div>
      <div class="risk-detail">
        <div>Risk Level: <span class="risk-label">{risk_label}</span></div>
        <div>Compliance Rate: <strong>{compliance_pct}%</strong></div>
        <div style="font-size:0.8rem;color:var(--muted);margin-top:0.3rem;">
          {total} checks executed &mdash; {pass_count} passed, {fail_count} failed, {warn_count} warnings
        </div>
      </div>
    </div>
    <div class="compliance">
      <div>CIS Benchmark: <strong>{cis_compliance}%</strong></div>
      <div>IEC 62443: <strong>{iec_compliance}%</strong></div>
    </div>
  </div>

  <div class="summary">
    <div class="summary-card total">
      <div class="number">{total}</div>
      <div class="label">Total Checks</div>
    </div>
    <div class="summary-card pass">
      <div class="number">{pass_count}</div>
      <div class="label">Passed</div>
    </div>
    <div class="summary-card fail">
      <div class="number">{fail_count}</div>
      <div class="label">Failed</div>
    </div>
    <div class="summary-card warn">
      <div class="number">{warn_count}</div>
      <div class="label">Warnings</div>
    </div>
  </div>

  <!-- Category Breakdown -->
  <div class="categories">
    <h2>Per-Category Breakdown</h2>
{category_rows}
  </div>

  <!-- Remediation Priority -->
  <div class="remediation-list">
    <h2>Remediation Priority</h2>
{remediation_items}
  </div>

  {baseline_section}

  <div class="filters">
    <button class="active" onclick="filterResults('all')">All</button>
    <button onclick="filterResults('FAIL')">Failures</button>
    <button onclick="filterResults('WARN')">Warnings</button>
    <button onclick="filterResults('PASS')">Passed</button>
  </div>

  <div class="results" id="results">
{result_rows}
  </div>

  <footer>
    Generated by edge-hardener v{version} &mdash; isecwire GmbH &mdash; {report_date}
  </footer>
</div>

<script>
function filterResults(status) {{
  document.querySelectorAll('.filters button').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.result-row').forEach(row => {{
    if (status === 'all' || row.dataset.status === status) {{
      row.style.display = '';
    }} else {{
      row.style.display = 'none';
    }}
  }});
}}
</script>
</body>
</html>
"""


def build_result_row(result: dict) -> str:
    """Build a single result row HTML."""
    status = result.get("status", "WARN")
    check = html.escape(result.get("check", "Unknown"))
    detail = html.escape(result.get("detail", ""))
    remediation = result.get("remediation", "")
    cis_id = result.get("cis_id", "")
    policy_violation = result.get("policy_violation", "")

    badge_class = status.lower()

    detail_html = ""
    if detail:
        detail_html = f'<div class="check-detail">{html.escape(detail)}</div>'

    cis_html = ""
    if cis_id:
        cis_html = f'<div class="check-cis">{html.escape(cis_id)}</div>'

    remediation_html = ""
    if remediation:
        rem_class = "remediation fail-rem" if status == "FAIL" else "remediation"
        remediation_html = (
            f'<div class="{rem_class}">Remediation: {html.escape(remediation)}</div>'
        )

    policy_html = ""
    if policy_violation:
        policy_html = f'<div class="policy-violation">Policy: {html.escape(policy_violation)}</div>'

    return (
        f'    <div class="result-row" data-status="{status}">\n'
        f'      <div><span class="badge {badge_class}">{status}</span></div>\n'
        f"      <div>\n"
        f'        <div class="check-name">{check}</div>\n'
        f"        {detail_html}\n"
        f"        {cis_html}\n"
        f"        {remediation_html}\n"
        f"        {policy_html}\n"
        f"      </div>\n"
        f"    </div>"
    )


def build_category_row(name: str, stats: dict) -> str:
    """Build a category breakdown row."""
    total = stats["total"]
    if total == 0:
        return ""
    pass_pct = stats["pass"] / total * 100
    warn_pct = stats["warn"] / total * 100
    fail_pct = stats["fail"] / total * 100
    score = int(pass_pct)

    return (
        f'    <div class="cat-row">\n'
        f'      <div>{html.escape(name)}</div>\n'
        f'      <div class="cat-bar">\n'
        f'        <div class="pass-seg" style="width:{pass_pct:.1f}%"></div>\n'
        f'        <div class="warn-seg" style="width:{warn_pct:.1f}%"></div>\n'
        f'        <div class="fail-seg" style="width:{fail_pct:.1f}%"></div>\n'
        f'      </div>\n'
        f'      <div>{score}%</div>\n'
        f'    </div>'
    )


def build_remediation_item(result: dict, index: int) -> str:
    """Build a remediation priority item."""
    status = result.get("status", "WARN")
    check = html.escape(result.get("check", "Unknown"))
    remediation = html.escape(result.get("remediation", ""))
    cis_id = result.get("cis_id", "")

    css_class = "rem-item fail" if status == "FAIL" else "rem-item"
    cis_html = f' <span class="rem-cis">({html.escape(cis_id)})</span>' if cis_id else ""

    return (
        f'    <div class="{css_class}">\n'
        f'      <div class="rem-check">{index}. [{status}] {check}{cis_html}</div>\n'
        f'      <div class="rem-action">{remediation}</div>\n'
        f'    </div>'
    )


def build_baseline_section(comparison: dict) -> str:
    """Build the baseline comparison section."""
    if not comparison:
        return ""

    parts = [
        '  <div class="baseline">',
        '    <h2>Baseline Comparison</h2>',
        f'    <p style="font-size:0.85rem;color:var(--muted);">Compared against: {html.escape(comparison["baseline_timestamp"])}</p>',
    ]

    if comparison["regressions"]:
        parts.append(f'    <h3 class="regression" style="margin-top:1rem;">Regressions ({len(comparison["regressions"])})</h3>')
        for r in comparison["regressions"]:
            parts.append(f'    <div class="regression" style="padding:0.3rem 0;font-size:0.85rem;">[-] {html.escape(r["check"])}: {r["was"]} &rarr; {r["now"]}</div>')

    if comparison["improved"]:
        parts.append(f'    <h3 class="improved" style="margin-top:1rem;">Improved ({len(comparison["improved"])})</h3>')
        for r in comparison["improved"]:
            parts.append(f'    <div class="improved" style="padding:0.3rem 0;font-size:0.85rem;">[+] {html.escape(r["check"])}: {r["was"]} &rarr; {r["now"]}</div>')

    if comparison["new_findings"]:
        parts.append(f'    <h3 class="new-finding" style="margin-top:1rem;">New Findings ({len(comparison["new_findings"])})</h3>')
        for r in comparison["new_findings"]:
            parts.append(f'    <div class="new-finding" style="padding:0.3rem 0;font-size:0.85rem;">[*] {html.escape(r["check"])}: {r["status"]}</div>')

    if not comparison["regressions"] and not comparison["new_findings"]:
        parts.append('    <p style="color:var(--pass);margin-top:0.5rem;">No regressions detected.</p>')

    parts.append('  </div>')
    return "\n".join(parts)


def generate_report(data: dict, baseline_data: dict = None) -> str:
    """Generate full HTML report from JSON data."""
    summary = data.get("summary", {})

    # Sort results: FAIL first, then WARN, then PASS
    order = {"FAIL": 0, "WARN": 1, "PASS": 2}
    results = sorted(
        data.get("results", []),
        key=lambda r: order.get(r.get("status", "WARN"), 1),
    )

    result_rows = "\n".join(build_result_row(r) for r in results)

    # Category breakdown
    categories = analyze_categories(data.get("results", []))
    category_rows = "\n".join(
        build_category_row(name, stats)
        for name, stats in sorted(categories.items())
        if stats["total"] > 0
    )

    # Remediation priority
    rem_list = remediation_priority(data.get("results", []))
    remediation_items = "\n".join(
        build_remediation_item(r, i + 1)
        for i, r in enumerate(rem_list[:20])
    )
    if not rem_list:
        remediation_items = '    <div style="color:var(--pass);font-size:0.9rem;">No remediation actions required.</div>'

    # Risk score
    score = compute_risk_score(data)
    comp_pct = compliance_percentage(data)

    # CIS compliance (checks with cis_id that passed)
    cis_results = [r for r in data.get("results", []) if r.get("cis_id")]
    cis_pass = sum(1 for r in cis_results if r.get("status") == "PASS")
    cis_compliance = round(cis_pass / len(cis_results) * 100, 1) if cis_results else 100.0

    # Policy
    policy = data.get("policy", "")
    policy_meta = f'<div><strong>Policy:</strong> {html.escape(policy)}</div>' if policy else ""

    # Baseline comparison
    comparison = None
    if baseline_data:
        comparison = compare_baselines(data, baseline_data)
    baseline_section = build_baseline_section(comparison)

    return HTML_TEMPLATE.format(
        hostname=html.escape(data.get("hostname", "unknown")),
        kernel=html.escape(data.get("kernel", "unknown")),
        arch=html.escape(data.get("arch", "unknown")),
        timestamp=html.escape(data.get("timestamp", "unknown")),
        version=html.escape(data.get("version", "2.0.0")),
        total=summary.get("total", 0),
        pass_count=summary.get("pass", 0),
        fail_count=summary.get("fail", 0),
        warn_count=summary.get("warn", 0),
        result_rows=result_rows,
        category_rows=category_rows,
        remediation_items=remediation_items,
        risk_score=score,
        risk_label=risk_label(score),
        risk_color=risk_color(score),
        compliance_pct=comp_pct,
        cis_compliance=cis_compliance,
        iec_compliance=comp_pct,  # proxy
        policy_meta=policy_meta,
        baseline_section=baseline_section,
        report_date=datetime.now().strftime("%Y-%m-%d %H:%M"),
    )


def generate_text_report(data: dict, baseline_data: dict = None) -> str:
    """Generate a plain-text report."""
    lines = []
    lines.append("=" * 70)
    lines.append("  edge-hardener Security Audit Report")
    lines.append("=" * 70)
    lines.append(f"  Host      : {data.get('hostname', 'unknown')}")
    lines.append(f"  Kernel    : {data.get('kernel', 'unknown')}")
    lines.append(f"  Arch      : {data.get('arch', 'unknown')}")
    lines.append(f"  Timestamp : {data.get('timestamp', 'unknown')}")
    lines.append(f"  Version   : {data.get('version', '2.0.0')}")
    if data.get("policy"):
        lines.append(f"  Policy    : {data['policy']}")
    lines.append("")

    summary = data.get("summary", {})
    score = compute_risk_score(data)
    comp = compliance_percentage(data)

    lines.append("  EXECUTIVE SUMMARY")
    lines.append("  " + "-" * 50)
    lines.append(f"  Risk Score      : {score}/100 ({risk_label(score)})")
    lines.append(f"  Compliance Rate : {comp}%")
    lines.append(f"  Total Checks    : {summary.get('total', 0)}")
    lines.append(f"  Passed          : {summary.get('pass', 0)}")
    lines.append(f"  Failed          : {summary.get('fail', 0)}")
    lines.append(f"  Warnings        : {summary.get('warn', 0)}")
    lines.append("")

    categories = analyze_categories(data.get("results", []))
    lines.append(ascii_radar_chart(categories))
    lines.append("")

    rem_list = remediation_priority(data.get("results", []))
    if rem_list:
        lines.append("  REMEDIATION PRIORITY")
        lines.append("  " + "-" * 50)
        for i, r in enumerate(rem_list[:15], 1):
            cis = f" ({r['cis_id']})" if r.get("cis_id") else ""
            lines.append(f"  {i:2d}. [{r['status']}] {r['check']}{cis}")
            lines.append(f"      -> {r['remediation']}")
        lines.append("")

    lines.append("=" * 70)
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Generate report from edge-hardener JSON output"
    )
    parser.add_argument(
        "input",
        help="Path to JSON results file (from edge_hardener.sh -j)",
    )
    parser.add_argument(
        "-o", "--output",
        default="report.html",
        help="Output file path (default: report.html)",
    )
    parser.add_argument(
        "--format",
        choices=["html", "text", "json"],
        default="html",
        help="Output format (default: html)",
    )
    parser.add_argument(
        "--baseline",
        default=None,
        help="Path to baseline JSON for comparison",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: Input file not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    try:
        data = json.loads(input_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"Error: Invalid JSON in {args.input}: {e}", file=sys.stderr)
        sys.exit(1)

    baseline_data = None
    if args.baseline:
        bp = Path(args.baseline)
        if bp.exists():
            try:
                baseline_data = json.loads(bp.read_text(encoding="utf-8"))
            except json.JSONDecodeError as e:
                print(f"Warning: Invalid baseline JSON: {e}", file=sys.stderr)

    if args.format == "html":
        report = generate_report(data, baseline_data)
    elif args.format == "text":
        report = generate_text_report(data, baseline_data)
    elif args.format == "json":
        # Enhanced JSON with computed fields
        data["risk_score"] = compute_risk_score(data)
        data["risk_label"] = risk_label(data["risk_score"])
        data["compliance_percentage"] = compliance_percentage(data)
        data["categories"] = analyze_categories(data.get("results", []))
        if baseline_data:
            data["baseline_comparison"] = compare_baselines(data, baseline_data)
        report = json.dumps(data, indent=2)
    else:
        report = generate_report(data, baseline_data)

    output_path = Path(args.output)
    output_path.write_text(report, encoding="utf-8")
    print(f"Report written to: {output_path.resolve()}")
    print(
        f"  {data.get('summary', {}).get('total', 0)} checks | "
        f"{data.get('summary', {}).get('pass', 0)} pass | "
        f"{data.get('summary', {}).get('fail', 0)} fail | "
        f"{data.get('summary', {}).get('warn', 0)} warn | "
        f"risk score: {compute_risk_score(data)}/100"
    )


if __name__ == "__main__":
    main()
