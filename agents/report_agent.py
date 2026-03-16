"""
HiveReaper v2 — ReportAgent (Real Output)
Compiles all validated findings into a structured JSON + Markdown report.
No external tools needed — pure Python + Grok synthesis.
"""

import json
from pathlib import Path
from datetime import datetime
from .base_agent import BaseAgent

REPORT_DIR = Path("reports")


class ReportAgent(BaseAgent):
    AGENT_NAME = "ReportAgent"

    async def _run_tools(self) -> dict[str, str]:
        # No tools to run — just aggregate everything from prior agents
        return {}

    def _build_task(self) -> str:
        ctx           = self.prior_context
        all_findings  = ctx.get("findings", [])
        validated     = ctx.get("validated_findings", [])
        domain_info   = ctx.get("domain_info", {})
        pivot_paths   = ctx.get("pivot_paths", [])
        hashes        = ctx.get("hashes_captured", [])
        hosts         = ctx.get("hosts_discovered", [])
        tech_stack    = ctx.get("tech_stack", {})
        vulns         = ctx.get("vulnerabilities_confirmed", [])
        creds         = ctx.get("credentials_found", [])
        shells        = ctx.get("shells_obtained", [])
        exposed       = ctx.get("exposed_paths", [])
        summaries     = ctx.get("agent_summaries", [])
        hints         = ctx.get("operator_hints", [])

        # Use validated findings if available, fall back to raw. Merge all sources.
        findings_src = validated if validated else all_findings
        # Add confirmed vulns that may not be in findings list
        confirmed_titles = {f.get("title","") for f in findings_src}
        for v in vulns:
            title = f"CONFIRMED: {v.get('vuln_type','vuln').upper()} on {v.get('target','')}"
            if title not in confirmed_titles:
                findings_src.append({
                    "finding_type": v.get("vuln_type","vulnerability"),
                    "title":        title,
                    "severity":     v.get("severity","high"),
                    "target":       v.get("target", self.target),
                    "detail":       v.get("evidence","") + " " + v.get("detail",""),
                })

        # Cap findings for prompt — full list goes to the JSON file, not Grok
        findings_for_prompt = findings_src[:25]
        findings_json = json.dumps(findings_for_prompt, indent=2)
        if len(findings_json) > 8000:
            # Hard cap: truncate individual detail fields
            for f in findings_for_prompt:
                if len(f.get("detail", "")) > 200:
                    f["detail"] = f["detail"][:200] + "…"
            findings_json = json.dumps(findings_for_prompt, indent=2)

        return f"""
{self._hints_block()}
You are ReportAgent. Write a professional penetration test report.
Use ONLY real findings from prior agents — do not invent anything.

Target:     {self.target}
Objective:  {self.objective}
Date:       {datetime.now().strftime('%Y-%m-%d')}
Hosts found: {len(hosts)}
Tech stack: {str(tech_stack)[:300]}
Domain info: {domain_info}
Pivot paths confirmed: {[p for p in pivot_paths if p.get('success')]}
Hashes captured: {len(hashes)}

All findings ({len(findings_src)} total — showing first 25):
{findings_json}

Return JSON:
{{
  "report": {{
    "title":             "Penetration Test Report — {self.target}",
    "date":              "{datetime.now().strftime('%Y-%m-%d')}",
    "target":            "{self.target}",
    "objective":         "{self.objective}",
    "risk_rating":       "critical|high|medium|low|informational",
    "executive_summary": "<3-5 sentence non-technical summary of what was found and the risk>",
    "attack_narrative":  "<paragraph describing the full attack chain end-to-end>",
    "statistics": {{
      "hosts_discovered": {len(hosts)},
      "total_findings":   {len(findings_src)},
      "critical": 0,
      "high":     0,
      "medium":   0,
      "low":      0,
      "info":     0
    }},
    "findings": [
      {{
        "id":             "FIND-001",
        "title":          "<finding title>",
        "severity":       "critical|high|medium|low|info",
        "cvss":           <score or null>,
        "cve":            "<CVE-ID or null>",
        "affected":       "<host/url/service>",
        "description":    "<technical description>",
        "evidence":       "<proof from tool output>",
        "impact":         "<business impact>",
        "remediation":    "<specific actionable fix steps>"
      }}
    ],
    "recommendations": [
      "<prioritised recommendation 1>",
      "<prioritised recommendation 2>"
    ],
    "hashes_for_cracking": {json.dumps(hashes[:10])},
    "pivot_paths_confirmed": {json.dumps([p for p in pivot_paths if p.get('success')][:5])}
  }},
  "findings": [],
  "opsec_cost": 0
}}
"""

    def _parse_result(self, raw: dict) -> dict:
        report = raw.get("report", {})
        if not report:
            return raw

        REPORT_DIR.mkdir(exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_target = self.target.replace("/", "_").replace(":", "_").replace(" ", "_")

        # Save JSON report
        json_path = REPORT_DIR / f"report_{ts}_{safe_target}.json"
        try:
            json_path.write_text(json.dumps(report, indent=2))
            self._log(f"[ReportAgent] JSON report saved: {json_path}", "success")
        except Exception as e:
            self._log(f"[ReportAgent] Could not save JSON report: {e}", "error")

        # Save Markdown report
        md_path = REPORT_DIR / f"report_{ts}_{safe_target}.md"
        try:
            md_path.write_text(self._render_markdown(report))
            self._log(f"[ReportAgent] Markdown report saved: {md_path}", "success")
        except Exception as e:
            self._log(f"[ReportAgent] Could not save Markdown report: {e}", "error")

        raw["findings"]   = []
        raw["report_path"] = str(json_path)
        return raw

    def _render_markdown(self, report: dict) -> str:
        sev_emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "🔵"}
        lines = [
            f"# {report.get('title', 'Penetration Test Report')}",
            f"**Date:** {report.get('date')}  ",
            f"**Target:** {report.get('target')}  ",
            f"**Risk Rating:** {report.get('risk_rating','').upper()}  ",
            "",
            "---",
            "",
            "## Executive Summary",
            report.get("executive_summary", ""),
            "",
            "## Attack Narrative",
            report.get("attack_narrative", ""),
            "",
            "## Statistics",
            f"| Metric | Count |",
            f"|--------|-------|",
        ]
        stats = report.get("statistics", {})
        for k, v in stats.items():
            lines.append(f"| {k.replace('_',' ').title()} | {v} |")

        lines += ["", "## Findings", ""]
        for f in report.get("findings", []):
            sev = f.get("severity", "info").lower()
            lines += [
                f"### {sev_emoji.get(sev,'▪')} {f.get('id','')} — {f.get('title','')}",
                f"**Severity:** {sev.upper()}  ",
                f"**Affected:** `{f.get('affected','')}`  ",
                f"**CVSS:** {f.get('cvss', 'N/A')}  ",
                "",
                f"**Description:** {f.get('description','')}",
                "",
                f"**Evidence:**",
                f"```",
                f"{f.get('evidence','')}",
                f"```",
                "",
                f"**Impact:** {f.get('impact','')}",
                "",
                f"**Remediation:** {f.get('remediation','')}",
                "",
                "---",
                "",
            ]

        lines += [
            "## Recommendations",
        ]
        for i, rec in enumerate(report.get("recommendations", []), 1):
            lines.append(f"{i}. {rec}")

        hashes = report.get("hashes_for_cracking", [])
        if hashes:
            lines += [
                "",
                "## Hashes for Offline Cracking",
                "```",
                *[f"{h.get('username')}:{h.get('hash')}" for h in hashes],
                "```",
            ]

        return "\n".join(lines)
