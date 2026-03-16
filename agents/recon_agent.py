"""
HiveReaper v2 — ReconAgent (Real Tools)

Tools used:
  nmap      — port discovery, service detection
  amass     — subdomain enumeration (passive)
  subfinder — fast subdomain enumeration
  dnsx      — DNS resolution and record query
  whatweb   — technology fingerprinting on web ports

Ghost mode: dnsx + amass passive only (no direct target connections)
Stealth+  : nmap -T2 + amass passive + subfinder
Normal/Loud: full nmap -sV + all tools
"""

import asyncio
from .base_agent import BaseAgent


class ReconAgent(BaseAgent):
    AGENT_NAME = "ReconAgent"

    async def _run_tools(self) -> dict[str, str]:
        outputs = {}
        target  = self.target
        timing  = self._nmap_timing()

        if self.opsec_mode == "ghost":
            # Ghost: passive DNS only — no direct connections
            outputs["dnsx"] = await self._run_cmd(
                ["dnsx", "-d", target, "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt",
                 "-resp", "-silent"],
                "dnsx passive DNS",
                timeout=60,
            )
            outputs["amass"] = await self._run_cmd(
                ["amass", "enum", "-passive", "-d", target, "-timeout", "120"],
                "amass passive enum",
                timeout=150,
            )
        else:
            # Subdomain enumeration
            sub_tasks = [
                self._run_cmd(
                    ["subfinder", "-d", target, "-silent", "-all"],
                    "subfinder",
                    timeout=120,
                ),
                self._run_cmd(
                    ["amass", "enum", "-passive", "-d", target,
                     "-timeout", "90", "-nocolor"],
                    "amass passive",
                    timeout=120,
                ),
                self._run_cmd(
                    ["dnsx", "-d", target, "-a", "-aaaa", "-cname", "-mx",
                     "-ns", "-txt", "-resp", "-silent"],
                    "dnsx records",
                    timeout=60,
                ),
            ]
            subfinder_out, amass_out, dnsx_out = await asyncio.gather(*sub_tasks)
            outputs["subfinder"] = subfinder_out
            outputs["amass"]     = amass_out
            outputs["dnsx"]      = dnsx_out

            # Combine discovered subdomains into a host list for nmap
            hosts_raw = set()
            import re as _re
            hosts_raw.add(target)
            for line in (subfinder_out + "\n" + amass_out).splitlines():
                line = line.strip()
                # Only accept clean domain/IP strings — reject ANSI, spaces, progress bars
                if (line and "." in line
                        and not line.startswith("ERROR")
                        and " " not in line
                        and "\x1b" not in line
                        and _re.match(r'^[a-zA-Z0-9._-]+$', line)):
                    hosts_raw.add(line)

            # Limit to 20 hosts in stealth/normal, all in loud
            host_limit = 10 if self.opsec_mode == "stealth" else 20
            hosts      = list(hosts_raw)[:host_limit]
            host_str   = " ".join(hosts)

            # nmap port scan
            if self.opsec_mode == "stealth":
                nmap_cmd = [
                    "nmap", timing, "-Pn", "--open",
                    "-p", "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,"
                           "1433,1723,3306,3389,5900,5985,8080,8443,8888",
                    "--randomize-hosts",
                    *hosts
                ]
            elif self.opsec_mode == "loud":
                nmap_cmd = [
                    "nmap", timing, "-Pn", "--open", "-p-",
                    "--min-rate", "5000",
                    *hosts
                ]
            else:  # normal
                nmap_cmd = [
                    "nmap", timing, "-Pn", "--open",
                    "-p", "1-10000",
                    *hosts
                ]

            outputs["nmap_ports"] = await self._run_cmd(
                nmap_cmd, "nmap port scan", timeout=300
            )

            # Service version detection on open ports found
            open_ports = self._extract_open_ports(outputs["nmap_ports"])
            if open_ports and self.opsec_mode != "stealth":
                svc_cmd = [
                    "nmap", timing, "-Pn", "-sV", "--version-intensity", "5",
                    "-p", ",".join(open_ports[:30]),
                    *hosts[:5]
                ]
                outputs["nmap_services"] = await self._run_cmd(
                    svc_cmd, "nmap service detection", timeout=180
                )

            # WhatWeb on HTTP/HTTPS ports
            web_hosts = self._extract_web_hosts(outputs["nmap_ports"], hosts)
            if web_hosts:
                whatweb_cmd = [
                    "whatweb", "--color=never", "--no-errors",
                    "-a", "1" if self.opsec_mode == "stealth" else "3",
                    *web_hosts[:10]
                ]
                outputs["whatweb"] = await self._run_cmd(
                    whatweb_cmd, "whatweb", timeout=120
                )

        return outputs

    def _extract_open_ports(self, nmap_out: str) -> list[str]:
        ports = []
        for line in nmap_out.splitlines():
            if "/tcp" in line and "open" in line:
                port = line.split("/")[0].strip()
                if port.isdigit():
                    ports.append(port)
        return ports

    def _extract_web_hosts(self, nmap_out: str, hosts: list[str]) -> list[str]:
        import re
        web_ports = set()
        for line in nmap_out.splitlines():
            if "/tcp" in line and "open" in line:
                p = line.split("/")[0].strip()
                if p in ("80", "443", "8080", "8443", "8000", "8888"):
                    web_ports.add(p)
        web_hosts = []
        for h in hosts[:5]:
            # Validate host looks like a real IP or hostname — no spaces, no ANSI
            h = h.strip()
            if not h or " " in h or "" in h:
                continue
            if not re.match(r'^[a-zA-Z0-9.-]+$', h):
                continue
            for p in web_ports:
                scheme = "https" if p in ("443", "8443") else "http"
                web_hosts.append(f"{scheme}://{h}:{p}")
        return web_hosts

    def _build_task(self) -> str:
        tool_outputs = self._cap_tool_outputs(max_bytes=10000)
        return f"""
{self._hints_block()}
You are ReconAgent. Parse the following REAL tool output collected from Kali Linux
against target: {self.target}
OpSec mode: {self.opsec_mode}
Objective: {self.objective}

--- REAL TOOL OUTPUT ---
{tool_outputs or "No tool output collected — all tools may be missing."}
--- END TOOL OUTPUT ---

Extract all findings from the real output above. Return JSON:
{{
  "summary": "<what was discovered>",
  "hosts_discovered": [
    {{
      "ip": "<ip>",
      "hostname": "<hostname or empty>",
      "open_ports": [<int>, ...],
      "os_guess": "<if detected>",
      "banner": "<service banner if seen>"
    }}
  ],
  "subdomains": ["<subdomain>", ...],
  "dns_records": {{"A": [], "MX": [], "NS": [], "TXT": [], "CNAME": []}},
  "web_targets": ["<http/https url>", ...],
  "findings": [
    {{
      "finding_type": "open_port|service|subdomain|info_disclosure|config_issue",
      "title": "<specific title with port/service/version>",
      "target": "<ip or hostname>",
      "severity": "info|low|medium|high|critical",
      "detail": "<exact detail from tool output>"
    }}
  ],
  "recommended_next": ["<what FingerprintAgent should focus on>"],
  "recommended_tools": {{
    "skip_web_tools": <true|false — true if WAF/firewall/403 blocks all web access>,
    "skip_reason": "<why web tools should be skipped, or empty>",
    "ftp_anon_found": <true|false — true if ftp-anon anonymous login seen in output>,
    "ftp_targets": ["<ip:21>"],
    "mail_ports_open": <true|false — true if 25/465/587/110/143/993/995 open>,
    "mail_targets": ["<ip:port>"],
    "priority_exploits": ["<service:version that should be exploited first>"],
    "skip_tools": ["nuclei|ffuf|sqlmap|searchsploit — list tools to skip and why"]
  }},
  "opsec_cost": <actual cost 0-15 based on what was run>
}}
"""

    def _parse_result(self, raw: dict) -> dict:
        for host in raw.get("hosts_discovered", []):
            for port in host.get("open_ports", []):
                raw.setdefault("findings", []).append({
                    "finding_type": "open_port",
                    "title":  f"{port}/tcp open — {host.get('hostname') or host.get('ip', self.target)}",
                    "target": host.get("ip", self.target),
                    "severity": "info",
                    "detail": host.get("banner", ""),
                })
        return raw
