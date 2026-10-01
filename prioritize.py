#!/usr/bin/env python3
"""Risk-based vulnerability remediation prioritizer.

Reads a Qualys-style CSV of findings and ranks them with a transparent,
documented scoring model:

    priority = severity_weight x asset_weight x age_factor x exploit_factor

    severity_weight : Critical=4, High=3, Medium=2, Low=1
    asset_weight    : from assets.json -- critical=1.5, high=1.25,
                      medium=1.0, low=0.75 (unlisted hosts default to medium)
    age_factor      : days since first_seen --
                      >180d: 1.5, >90d: 1.3, >30d: 1.15, else 1.0
    exploit_factor  : 1.5 when a public exploit exists, else 1.0

Why this model: raw CVSS alone buries critical bugs on lab printers above
high bugs on production databases. Weighting by asset criticality, exposure
time, and exploitability produces a queue a team can actually work.

Outputs a ranked console table and a Markdown report with SLA targets:

    Critical: 15 days | High: 30 days | Medium: 90 days | Low: 180 days

Usage:
    python prioritize.py sample_findings.csv --assets assets.json
    python prioritize.py sample_findings.csv --assets assets.json \\
        --as-of 2026-09-30 --report remediation_plan.md
"""

from __future__ import annotations

import argparse
import csv
import json
from datetime import date, datetime

SEVERITY_WEIGHT = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
ASSET_WEIGHT = {"critical": 1.5, "high": 1.25, "medium": 1.0, "low": 0.75}
SLA_DAYS = {"Critical": 15, "High": 30, "Medium": 90, "Low": 180}
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def parse_date(value: str) -> date:
    return datetime.strptime(value.strip(), "%Y-%m-%d").date()


def age_factor(days_old: int) -> float:
    if days_old > 180:
        return 1.5
    if days_old > 90:
        return 1.3
    if days_old > 30:
        return 1.15
    return 1.0


def load_assets(path: str) -> dict[str, str]:
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    return {str(k): str(v).lower() for k, v in data.items()}


def truthy(value: str | None) -> bool:
    return str(value or "").strip().lower() in ("true", "yes", "1", "y")


def score_finding(row: dict, assets: dict[str, str], as_of: date) -> dict:
    severity = row["severity"].strip()
    sev_w = SEVERITY_WEIGHT.get(severity, 1)

    asset_tier = assets.get(row["ip"].strip(),
                            assets.get(row["hostname"].strip(), "medium"))
    asset_w = ASSET_WEIGHT.get(asset_tier, 1.0)

    first_seen = parse_date(row["first_seen"])
    last_seen = parse_date(row["last_seen"])
    age_days = max((as_of - first_seen).days, 0)
    age_f = age_factor(age_days)

    exploit = truthy(row.get("exploit_available"))
    exploit_f = 1.5 if exploit else 1.0

    score = round(sev_w * asset_w * age_f * exploit_f, 2)

    sla = SLA_DAYS.get(severity, 180)
    due = last_seen.fromordinal(last_seen.toordinal() + sla)
    status = "OVERDUE" if due < as_of else f"due {due.isoformat()}"

    return {
        "score": score,
        "severity": severity,
        "ip": row["ip"].strip(),
        "hostname": row["hostname"].strip(),
        "title": row["title"].strip(),
        "cve": row.get("cve", "").strip() or "-",
        "cvss": row.get("cvss", "").strip() or "-",
        "port": row.get("port", "").strip() or "-",
        "age_days": age_days,
        "exploit": exploit,
        "asset_tier": asset_tier,
        "sla_days": sla,
        "due": due.isoformat(),
        "status": status,
        # Debug string showing exactly how the score was built.
        "math": f"{sev_w} x {asset_w} x {age_f} x {exploit_f}",
    }


def print_table(findings: list[dict]) -> None:
    print(f"\nRemediation Queue - {len(findings)} findings ranked by priority\n")
    header = (f"{'Rk':>3} {'Score':>6} {'Sev':<8} {'IP':<13} {'Host':<13} "
              f"{'CVE':<16} {'Age':>4} {'Status':<14} Title")
    print(header)
    print("-" * len(header))
    for i, f in enumerate(findings, 1):
        title = f["title"][:52]
        print(f"{i:>3} {f['score']:>6.2f} {f['severity']:<8} {f['ip']:<13} "
              f"{f['hostname']:<13} {f['cve']:<16} {f['age_days']:>4}d "
              f"{f['status']:<14} {title}")


def print_breakdown(findings: list[dict]) -> None:
    print("\nTop 5 - score breakdown (sev x asset x age x exploit):")
    for f in findings[:5]:
        print(f"  {f['score']:>6.2f} = {f['math']:<22} {f['ip']} "
              f"{f['title'][:45]}")


def write_report(path: str, findings: list[dict], args: argparse.Namespace,
                 as_of: date) -> None:
    lines = [
        "# Vulnerability Remediation Plan",
        "",
        f"Generated: {as_of.isoformat()} from `{args.csv}` "
        f"({len(findings)} findings)",
        "",
        "## Scoring model",
        "",
        "`priority = severity_weight x asset_weight x age_factor x "
        "exploit_factor`",
        "",
        "| Factor | Values |",
        "|---|---|",
        "| severity_weight | Critical=4, High=3, Medium=2, Low=1 |",
        "| asset_weight | critical=1.5, high=1.25, medium=1.0, low=0.75 |",
        "| age_factor | >180d=1.5, >90d=1.3, >30d=1.15, else 1.0 |",
        "| exploit_factor | 1.5 if a public exploit exists, else 1.0 |",
        "",
        "## SLA targets",
        "",
        "| Severity | Remediate within |",
        "|---|---|",
    ]
    lines += [f"| {sev} | {days} days |" for sev, days in SLA_DAYS.items()]
    lines += ["", "## Ranked remediation queue", "",
              "| Rank | Score | Severity | Host (IP) | Finding | CVE | "
              "Age | SLA due | Status |",
              "|---|---|---|---|---|---|---|---|---|"]
    for i, f in enumerate(findings, 1):
        lines.append(
            f"| {i} | {f['score']:.2f} | {f['severity']} | "
            f"{f['hostname']} ({f['ip']}) | {f['title']} | {f['cve']} | "
            f"{f['age_days']}d | {f['due']} | {f['status']} |")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    print(f"\nMarkdown report written to {path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rank vulnerability findings by risk-based priority.")
    parser.add_argument("csv", help="Qualys-style findings CSV")
    parser.add_argument("--assets", default="assets.json",
                        help="JSON mapping of IP/hostname -> criticality tier")
    parser.add_argument("--as-of", default=None,
                        help="reference date YYYY-MM-DD (default: today)")
    parser.add_argument("--report", default="remediation_plan.md",
                        help="Markdown report output path")
    parser.add_argument("--top", type=int, default=0,
                        help="only show the top N findings (0 = all)")
    args = parser.parse_args()

    as_of = parse_date(args.as_of) if args.as_of else date.today()
    assets = load_assets(args.assets)

    with open(args.csv, newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))

    required = {"ip", "hostname", "title", "severity", "first_seen",
                "last_seen"}
    missing = required - set(rows[0].keys()) if rows else required
    if missing:
        raise SystemExit(f"CSV is missing required columns: "
                         f"{', '.join(sorted(missing))}")

    findings = [score_finding(r, assets, as_of) for r in rows]
    findings.sort(key=lambda f: (-f["score"], SEVERITY_ORDER[f["severity"]]))

    shown = findings[:args.top] if args.top > 0 else findings
    print_table(shown)
    print_breakdown(findings)
    write_report(args.report, findings, args, as_of)


if __name__ == "__main__":
    main()
