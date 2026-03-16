"""
HiveReaper v2 — Base Agent (Real Tool Edition)
Provides async subprocess execution, output capture, and Grok interpretation.
All pentest agents inherit from this.
"""

import json
import asyncio
import logging
import shutil
import os
from datetime import datetime
from typing import Callable, Optional, Any
from openai import AsyncOpenAI

logger = logging.getLogger(__name__)

GROK_MODEL = "grok-3"

BASE_AGENT_SYSTEM = """You are an autonomous red-team agent within the HiveReaper pentest swarm.
You receive REAL tool output from actual tools run on Kali Linux.
Your job is to parse that output, identify findings, and return structured JSON.
Always respond with valid JSON only — no markdown, no prose outside JSON.
Be precise, professional, and security-focused.
Every finding must be grounded in the actual tool output provided — do not invent findings."""


class BaseAgent:
    AGENT_NAME  = "BaseAgent"
    TOOL_TIMEOUT = 300

    def __init__(self, lane_id, target, objective, opsec_mode,
                 prior_context, on_log, on_finding, grok_client):
        self.lane_id        = lane_id
        self.target         = target
        self.objective      = objective
        self.opsec_mode     = opsec_mode
        self.prior_context  = prior_context
        self.on_log         = on_log
        self.on_finding     = on_finding
        self.client         = grok_client
        self._tool_outputs: dict[str, str] = {}
        self._findings_emitted: list[dict] = []

    async def run(self) -> dict:
        self._log(f"[{self.lane_id}] {self.AGENT_NAME} starting — target: {self.target}", "info")
        try:
            self._tool_outputs = await self._run_tools()
        except Exception as e:
            self._log(f"[{self.AGENT_NAME}] Tool execution error: {e}", "error")
            self._tool_outputs = {}

        task   = self._build_task()
        system = self._system_prompt()
        raw    = await self._ask_grok(system, task)
        result = self._parse_result(raw)

        for finding in result.get("findings", []):
            # Guard: Grok occasionally returns strings instead of dicts
            if isinstance(finding, str):
                self._emit_finding({
                    "finding_type": "info",
                    "title":        finding[:200],
                    "severity":     "info",
                    "detail":       finding,
                })
            elif isinstance(finding, dict):
                self._emit_finding(finding)

        self._log(
            f"[{self.lane_id}] {self.AGENT_NAME} done — "
            f"{len(result.get('findings', []))} findings, "
            f"opsec cost: {result.get('opsec_cost', 0)}%",
            "success",
        )
        return result

    def _system_prompt(self) -> str:
        return BASE_AGENT_SYSTEM

    async def _run_tools(self) -> dict[str, str]:
        return {}

    def _build_task(self) -> str:
        return f"Analyse target: {self.target}\nObjective: {self.objective}"

    def _parse_result(self, raw: dict) -> dict:
        return raw

    async def _run_cmd(self, cmd: list[str], label: str,
                       timeout: int = None, input_data: str = None) -> str:
        timeout = timeout or self.TOOL_TIMEOUT
        binary  = cmd[0]

        if not shutil.which(binary):
            self._log(f"[{self.AGENT_NAME}] NOT FOUND: {binary} — skipping", "warning")
            return f"ERROR: {binary} not found in PATH. Install it first."

        self._log(
            f"[{self.lane_id}] ▶ {label}: {' '.join(str(c) for c in cmd[:8])}"
            f"{'…' if len(cmd) > 8 else ''}",
            "info",
        )
        try:
            stdin_pipe = asyncio.subprocess.PIPE if input_data else None
            proc = await asyncio.create_subprocess_exec(
                *[str(c) for c in cmd],
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                stdin=stdin_pipe,
                env=os.environ.copy(),
            )
            stdin_bytes = input_data.encode() if input_data else None
            try:
                stdout, stderr = await asyncio.wait_for(
                    proc.communicate(input=stdin_bytes), timeout=timeout
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.communicate()
                self._log(f"[{self.AGENT_NAME}] {label} timed out after {timeout}s", "warning")
                return f"TIMEOUT after {timeout}s — partial results may be missing"

            out = stdout.decode("utf-8", errors="replace").strip()
            err = stderr.decode("utf-8", errors="replace").strip()
            combined = out if out else err
            # Strip ANSI escape codes and progress bars that tools like amass emit
            combined = self._strip_ansi(combined)
            self._log(f"[{self.AGENT_NAME}] {label} ✓ ({len(combined)} bytes)", "success")
            return combined[:8000]  # cap to avoid Grok token overflow

        except Exception as e:
            self._log(f"[{self.AGENT_NAME}] {label} failed: {e}", "error")
            return f"ERROR: {e}"

    async def _ask_grok(self, system: str, user_msg: str, max_tokens: int = 3000) -> dict:
        for attempt in range(3):
            try:
                response = await self.client.chat.completions.create(
                    model=GROK_MODEL,
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user",   "content": user_msg},
                    ],
                    temperature=0.1,
                    max_tokens=max_tokens,
                    timeout=90,
                )
                raw = response.choices[0].message.content.strip()
                if raw.startswith("```"):
                    raw = raw.split("```")[1]
                    if raw.startswith("json"):
                        raw = raw[4:]
                return json.loads(raw)
            except json.JSONDecodeError as e:
                self._log(f"[{self.AGENT_NAME}] Grok JSON parse error: {e}", "error")
                return {"findings": [], "opsec_cost": 0, "error": str(e)}
            except Exception as e:
                if attempt < 2:
                    wait = 10 * (attempt + 1)
                    self._log(
                        f"[{self.AGENT_NAME}] Grok timeout (attempt {attempt + 1}/3) — "
                        f"retrying in {wait}s",
                        "warning",
                    )
                    await asyncio.sleep(wait)
                else:
                    self._log(f"[{self.AGENT_NAME}] Grok failed after 3 attempts: {e}", "error")
                    return {"findings": [], "opsec_cost": 0, "error": str(e)}

    def _cap_tool_outputs(self, max_bytes: int = 10000) -> str:
        """Combine and hard-cap all tool outputs before sending to Grok.

        Prevents token overflow / API timeouts when multiple slow tools
        each return several KB of output.
        """
        parts = []
        total = 0
        for name, out in self._tool_outputs.items():
            if not out or out.startswith("ERROR") or out.startswith("TIMEOUT"):
                continue
            chunk = f"=== {name.upper()} ===\n{out}"
            if total + len(chunk) > max_bytes:
                remaining = max_bytes - total
                if remaining > 300:
                    parts.append(chunk[:remaining] + "\n[TRUNCATED]")
                break
            parts.append(chunk)
            total += len(chunk)
        return "\n\n".join(parts) or "No tool output collected."

    def _emit_finding(self, finding: dict):
        finding.setdefault("lane_id",      self.lane_id)
        finding.setdefault("agent",        self.AGENT_NAME)
        finding.setdefault("target",       self.target)
        finding.setdefault("timestamp",    datetime.now().isoformat())
        finding.setdefault("severity",     "info")
        finding.setdefault("finding_type", "generic")
        self._findings_emitted.append(finding)
        self.on_finding(finding)

    def _log(self, msg: str, level: str = "info"):
        self.on_log(msg, level)

    def _prior(self, key: str, default: Any = None) -> Any:
        return self.prior_context.get(key, default)

    def _hints_block(self) -> str:
        """
        Returns a formatted block of operator hints to inject into any
        agent prompt. Empty string if no hints. Called in _build_task().
        """
        hints = self.prior_context.get("operator_hints", [])
        if not hints:
            return ""
        lines = ["\n=== OPERATOR HINTS — HIGHEST PRIORITY — ACT ON THESE IMMEDIATELY ==="]
        for i, h in enumerate(hints, 1):
            lines.append(f"  {i}. {h}")
        lines.append(
            "These hints come directly from the human operator watching the campaign. "
            "Override your normal plan if needed to follow them. "
            "If a hint mentions a specific tool, CVE, or technique — use it now."
        )
        lines.append("=== END OPERATOR HINTS ===\n")
        return "\n".join(lines)

    def _tool_out(self, name: str) -> str:
        return self._tool_outputs.get(name, "")

    def _nmap_timing(self) -> str:
        """Return the nmap timing flag for the current opsec mode."""
        return {
            "ghost":   "-T1",
            "stealth": "-T2",
            "normal":  "-T3",
            "loud":    "-T4",
        }.get(self.opsec_mode, "-T3")

    def _opsec_constraint(self) -> str:
        return {
            "ghost":   "PASSIVE ONLY — no active probing whatsoever",
            "stealth": "LOW AND SLOW — -T2 timing, randomised delays",
            "normal":  "STANDARD — normal pentesting pace, -T3",
            "loud":    "AGGRESSIVE — -T4/-T5, maximise speed and coverage",
        }.get(self.opsec_mode, "STANDARD")

    @staticmethod
    def _strip_ansi(text):
        import re
        text = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', text)
        text = re.sub(r'\x1b[\(\)][ABab]', '', text)
        text = re.sub(r'[\x0e\x0f]', '', text)
        lines_out = []
        for line in text.split('\n'):
            if '\r' in line:
                line = line.split('\r')[-1]
            s = line.strip()
            if re.match(r'^\d+ / \d+ \[', s):
                continue
            if re.match(r'^0\.00%', s):
                continue
            if re.match(r'^\s*\d+\.\d+% \? p/s', s):
                continue
            lines_out.append(line)
        result = '\n'.join(lines_out)
        result = re.sub(r'\n{3,}', '\n\n', result)
        return result.strip()
