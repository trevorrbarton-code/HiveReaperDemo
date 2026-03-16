"""
HiveReaper v2 — FingerprintAgent (Real Tools)

Tools used:
  nmap -sV --script    — deep service/version + NSE vuln scripts
  nikto                — web server vulnerability scanner
  wafw00f              — WAF detection
  httpx                — HTTP probing, tech detection, status codes
  whatweb              — CMS / framework fingerprinting
"""

import asyncio
from .base_agent import BaseAgent


class FingerprintAgent(BaseAgent):
    AGENT_NAME = "FingerprintAgent"

    async def _run_tools(self) -> dict[str, str]:
        outputs     = {}
        hosts       = self._prior("hosts_discovered", [])
        web_targets = self._prior("web_targets", [])
        subdomains  = self._prior("subdomains", [])
        timing      = self._nmap_timing()

        # Build IP list from recon
        ips = [h.get("ip") or h.get("hostname") for h in hosts if h.get("ip") or h.get("hostname")]
        if not ips:
            ips = [self.target]
        ips = list(dict.fromkeys(ips))[:10]  # dedupe, max 10

        # Build URL list
        urls = list(dict.fromkeys(web_targets))[:15]
        if not urls:
            urls = [f"http://{ip}" for ip in ips[:3]]

        tasks = {}

        # ── nmap deep service scan with NSE scripts ──
        if self.opsec_mode != "ghost":
            scripts = (
                "banner,http-title,http-server-header,http-headers,"
                "ssl-cert,ssl-enum-ciphers,ssh-auth-methods,"
                "ftp-anon,smtp-open-relay,dns-recursion,"
                "smb-security-mode,rdp-enum-encryption"
            )
            nmap_cmd = [
                "nmap", timing, "-Pn", "-sV",
                "--version-intensity", "7",
                "--script", scripts,
                "-p", "21,22,23,25,53,80,110,111,135,139,143,443,445,"
                      "993,995,1433,1723,3306,3389,5900,5985,8080,8443",
                *ips
            ]
            tasks["nmap_deep"] = self._run_cmd(nmap_cmd, "nmap deep scan", timeout=300)

        # ── httpx — HTTP probing ──
        if urls and self.opsec_mode != "ghost":
            httpx_cmd = [
                "httpx", "-silent",
                "-status-code", "-title", "-tech-detect",
                "-web-server", "-content-type",
                "-follow-redirects", "-timeout", "10",
                "-l", "/dev/stdin",
            ]
            tasks["httpx"] = self._run_cmd(
                httpx_cmd, "httpx probe",
                timeout=120,
                input_data="\n".join(urls),
            )

        # ── wafw00f — WAF detection ──
        if urls and self.opsec_mode in ("normal", "loud"):
            wafw_targets = urls[:5]
            tasks["wafw00f"] = self._run_cmd(
                ["wafw00f", "-a", *wafw_targets],
                "wafw00f WAF detection",
                timeout=60,
            )

        # nikto removed — ignores -maxtime on many installs, blocks lane for 150s+
        # nmap --script http-headers,banner covers the same ground faster.

        # ── whatweb — CMS/framework detection ──
        if urls:
            aggression = "1" if self.opsec_mode == "stealth" else "3"
            tasks["whatweb"] = self._run_cmd(
                ["whatweb", "--color=never", "--no-errors", f"-a{aggression}", *urls[:8]],
                "whatweb fingerprint",
                timeout=120,
            )

        # ── wpscan — WordPress scanner (auto-triggered if WP detected or hinted) ──
        hints     = self.prior_context.get("operator_hints", [])
        hint_text = " ".join(hints).lower()
        prior_out = str(self.prior_context).lower()
        wp_hinted = "wpscan" in hint_text or "wordpress" in hint_text
        wp_found  = "wordpress" in prior_out or "wp-content" in prior_out or "wp-login" in prior_out

        if (wp_hinted or wp_found) and urls and self.opsec_mode != "ghost":
            wp_targets = [u for u in urls if "443" in u or "https" in u] or urls[:2]
            for wp_url in wp_targets[:2]:
                tasks[f"wpscan_{wp_url.split('/')[-1] or 'site'}"] = self._run_cmd(
                    [
                        "wpscan", "--url", wp_url,
                        "--no-banner", "--disable-tls-checks",
                        "--enumerate", "vp,vt,u,cb,dbe",
                        "--random-user-agent",
                        "--format", "cli-no-color",
                    ],
                    f"wpscan {wp_url}",
                    timeout=180,
                )
            self._log(
                f"[FingerprintAgent] WordPress detected/hinted — running wpscan on {wp_targets[:2]}",
                "info",
            )

        # Run all async tasks
        pending = {k: v for k, v in tasks.items() if asyncio.iscoroutine(v)}
        for k, v in tasks.items():
            if isinstance(v, str):
                outputs[k] = v

        if pending:
            keys    = list(pending.keys())
            results = await asyncio.gather(*pending.values())
            for k, r in zip(keys, results):
                outputs[k] = r

        return outputs

    def _build_task(self) -> str:
        tool_outputs = self._cap_tool_outputs(max_bytes=10000)
        hosts_ctx = self._prior("hosts_discovered", [])
        return f"""
{self._hints_block()}
You are FingerprintAgent. Parse the following REAL tool output from Kali Linux.
Target: {self.target}
OpSec mode: {self.opsec_mode}
Prior recon context: {hosts_ctx[:5]}

--- REAL TOOL OUTPUT ---
{tool_outputs or "No tool output — tools may be missing or target unreachable."}
--- END ---

Extract every version number, technology, CVE hint, and configuration issue visible
in the tool output. Cross-reference versions with known CVEs where obvious.

Return JSON:
{{
  "tech_stack": {{
    "<ip_or_host>": {{
      "web_server": "<name + version if found>",
      "framework":  "<name + version or null>",
      "cms":        "<name + version or null>",
      "language":   "<php/python/java/etc or null>",
      "waf":        "<name or none>",
      "ssl_info":   "<cert CN, expiry, cipher issues>",
      "open_services": ["<service:version>", ...]
    }}
  }},
  "potential_cves": [
    {{
      "cve_id":      "CVE-YYYY-NNNNN",
      "component":   "<component + version from output>",
      "cvss":        <score>,
      "description": "<brief description>",
      "target":      "<affected host>",
      "exploitable": <true|false>,
      "evidence":    "<exact line from tool output that triggered this>"
    }}
  ],
  "interesting_endpoints": [
    {{
      "url":          "<url>",
      "status_code":  <int or null>,
      "title":        "<page title>",
      "note":         "<why interesting>",
      "auth_required": <true|false>
    }}
  ],
  "misconfigurations": [
    {{
      "issue":    "<misconfiguration name>",
      "target":   "<host>",
      "detail":   "<exact evidence from output>",
      "severity": "low|medium|high|critical"
    }}
  ],
  "findings": [
    {{
      "finding_type": "fingerprint|tech_stack|cve|config_issue|info_disclosure|ssl_issue",
      "title":        "<specific title with version numbers>",
      "target":       "<host>",
      "severity":     "info|low|medium|high|critical",
      "detail":       "<exact evidence from tool output>"
    }}
  ],
  "exploit_targets": ["<host:port or url>"],
  "opsec_cost": <0-25>
}}
"""

    def _parse_result(self, raw: dict) -> dict:
        for cve in raw.get("potential_cves", []):
            cvss = cve.get("cvss", 0)
            sev  = "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low"
            raw.setdefault("findings", []).append({
                "finding_type": "cve",
                "title":  f"{cve.get('cve_id','CVE-?')} — {cve.get('component','')}",
                "target": cve.get("target", self.target),
                "severity": sev,
                "detail": (
                    f"CVSS {cvss} | {cve.get('description','')} | "
                    f"Evidence: {cve.get('evidence','')}"
                ),
            })
        return raw
