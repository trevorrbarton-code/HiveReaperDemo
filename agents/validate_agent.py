"""
HiveReaper v2 — ValidateAgent (Real Tools)

Tools used:
  nmap --script vuln   — verify open vulnerabilities with NSE vuln scripts
  nuclei (CVE tags)    — cross-verify CVE findings from ExploitAgent
  curl                 — manually verify exposed endpoints

ValidateAgent takes raw findings from ExploitAgent, re-probes the
confirmed ones, removes false positives, and assigns final CVSS scores.
"""

import asyncio
import json
from .base_agent import BaseAgent


class ValidateAgent(BaseAgent):
    AGENT_NAME = "ValidateAgent"

    async def _run_tools(self) -> dict[str, str]:
        if self.opsec_mode == "ghost":
            return {}

        outputs     = {}
        raw_vulns   = self._prior("vulnerabilities_confirmed", [])
        web_targets = self._prior("web_targets", [])
        hosts       = self._prior("hosts_discovered", [])
        all_finds   = self._prior("findings", [])
        self._log(
            f"[ValidateAgent] Received: {len(all_finds)} findings, "
            f"{len(raw_vulns)} confirmed vulns, "
            f"{len(hosts)} hosts to verify",
            "info",
        )
        timing     = self._nmap_timing()

        ips = list(dict.fromkeys(
            h.get("ip") or h.get("hostname")
            for h in hosts
            if h.get("ip") or h.get("hostname")
        ))[:5]

        # ── nmap targeted validation — scripts matched to discovered services ──
        if ips and self.opsec_mode in ("normal", "loud"):
            # Build a targeted script list from what recon actually found,
            # rather than --script vuln,exploit (too slow, hits every port).
            open_ports_all = set()
            for h in hosts:
                open_ports_all.update(str(p) for p in h.get("open_ports", []))

            scripts = []
            port_list = []

            # Always run: SSL issues, headers, banners
            scripts += ["ssl-heartbleed", "ssl-poodle", "ssl-dh-params",
                        "http-server-header", "banner"]
            port_list += ["80", "443", "8080", "8443"]

            if any(p in open_ports_all for p in ("21",)):
                scripts += ["ftp-anon", "ftp-vsftpd-backdoor"]
                port_list.append("21")

            if any(p in open_ports_all for p in ("22", "6395")):
                scripts += ["ssh-auth-methods", "ssh-hostkey"]
                port_list += [p for p in ("22", "6395") if p in open_ports_all]

            if any(p in open_ports_all for p in ("25", "465", "587")):
                scripts += ["smtp-open-relay", "smtp-vuln-cve2010-4344",
                            "smtp-commands"]
                port_list += [p for p in ("25", "465", "587") if p in open_ports_all]

            if any(p in open_ports_all for p in ("53",)):
                scripts += ["dns-recursion", "dns-zone-transfer"]
                port_list.append("53")

            if any(p in open_ports_all for p in ("110", "143", "993", "995")):
                scripts += ["imap-capabilities", "pop3-capabilities"]
                port_list += [p for p in ("110","143","993","995") if p in open_ports_all]

            if any(p in open_ports_all for p in ("139", "445")):
                scripts += ["smb-vuln-ms17-010", "smb-security-mode",
                            "smb-vuln-cve-2020-0796", "smb2-security-mode"]
                port_list += [p for p in ("139", "445") if p in open_ports_all]

            if any(p in open_ports_all for p in ("2082", "2083", "2086", "2087")):
                scripts += ["http-title", "http-auth-finder"]
                port_list += [p for p in ("2082","2083","2086","2087") if p in open_ports_all]

            # Fallback: include all discovered ports
            for h in hosts:
                port_list += [str(p) for p in h.get("open_ports", [])]

            port_str    = ",".join(dict.fromkeys(port_list))[:200]
            script_str  = ",".join(dict.fromkeys(scripts))

            vuln_cmd = [
                "nmap", timing, "-Pn",
                "--script", script_str,
                "-p", port_str or "21,22,25,53,80,110,143,443,587,993,995",
                *ips
            ]
            outputs["nmap_vuln"] = await self._run_cmd(
                vuln_cmd, "nmap targeted validation", timeout=180
            )

        # ── nuclei CVE verification on confirmed targets ──
        confirmed_targets = [v.get("target") for v in raw_vulns if v.get("exploitable")]
        confirmed_targets = list(dict.fromkeys(
            t for t in confirmed_targets if t
        ))[:10]

        if confirmed_targets:
            cve_ids = [
                v.get("cve_id") or v.get("vuln_type")
                for v in self._prior("potential_cves", [])
                if v.get("cve_id")
            ][:10]
            tags = "cve,exposed-panels,default-login"

            outputs["nuclei_verify"] = await self._run_cmd(
                [
                    "nuclei", "-silent", "-no-color",
                    "-list", "/dev/stdin",
                    "-tags", tags,
                    "-severity", "medium,high,critical",
                    "-c", "10",
                    "-timeout", "10",
                ],
                "nuclei CVE verification",
                timeout=180,
                input_data="\n".join(confirmed_targets),
            )

        # ── curl — verify exposed endpoints manually ──
        exposed = self._prior("exposed_paths", [])
        if exposed and self.opsec_mode in ("normal", "loud"):
            curl_checks = await asyncio.gather(*[
                self._run_cmd(
                    [
                        "curl", "-sI",
                        "--max-time", "8",
                        "--user-agent", "Mozilla/5.0 (compatible; HiveReaper/2.0)",
                        p.get("url", ""),
                    ],
                    f"curl verify {p.get('url','')[:50]}",
                    timeout=15,
                )
                for p in exposed[:10]
                if p.get("url")
            ])
            outputs["curl_verify"] = "\n\n".join(
                f"URL: {p.get('url')}\n{r}"
                for p, r in zip(exposed[:10], curl_checks)
            )

        return outputs

    def _build_task(self) -> str:
        tool_outputs = self._cap_tool_outputs(max_bytes=8000)
        raw_findings = self._prior("findings", [])
        raw_vulns    = self._prior("vulnerabilities_confirmed", [])
        # Cap findings dump — large lists blow Grok's context
        findings_preview = json.dumps(raw_findings[:15], indent=2)
        vulns_preview    = json.dumps(raw_vulns[:8], indent=2)
        return f"""
{self._hints_block()}
You are ValidateAgent. Your job is quality control.

You have REAL re-verification tool output from Kali Linux AND the raw findings
from previous agents. Cross-reference them to confirm or dismiss each finding.

Target: {self.target}

Raw findings to validate ({len(raw_findings)} total — showing first 15):
{findings_preview}

Raw vulnerabilities to verify:
{vulns_preview}

--- REAL VERIFICATION TOOL OUTPUT ---
{tool_outputs or "No re-verification tools ran (stealth/ghost mode or tools missing)."}
--- END ---

Rules:
1. A finding is CONFIRMED if it appears in tool output OR was confirmed by nuclei/nmap vuln
2. A finding is UNCONFIRMED if it was only reported by one tool with no corroboration
3. A finding is FALSE POSITIVE if re-verification shows it does not exist
4. Assign CVSS scores based on standard CVSS v3.1 methodology
5. Severity must match the CVSS: critical≥9, high≥7, medium≥4, low<4

Return JSON:
{{
  "validated_findings": [
    {{
      "finding_type":    "<type>",
      "title":           "<clean specific title>",
      "target":          "<target>",
      "severity":        "info|low|medium|high|critical",
      "cvss":            <0.0-10.0>,
      "confirmed":       <true|false>,
      "false_positive":  <false>,
      "confidence":      "confirmed|likely|unconfirmed",
      "business_impact": "<one sentence>",
      "remediation":     "<specific actionable fix>",
      "detail":          "<technical evidence>",
      "tool_used":       "<which tool confirmed>"
    }}
  ],
  "summary": {{
    "total_raw": {len(raw_findings)},
    "confirmed": <n>,
    "unconfirmed": <n>,
    "false_positives_removed": <n>,
    "critical": <n>,
    "high": <n>,
    "medium": <n>,
    "low": <n>,
    "info": <n>
  }},
  "findings": [],
  "opsec_cost": <0-10>
}}
"""

    def _parse_result(self, raw: dict) -> dict:
        raw["findings"] = [
            f for f in raw.get("validated_findings", [])
            if not f.get("false_positive", False)
        ]
        return raw
