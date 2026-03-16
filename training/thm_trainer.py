"""
HiveReaper v2 — TryHackMe Training Mode
Runs the full swarm against a THM box, detects flags, records the full
attack path, and feeds it all into the memory system.

Usage:
  trainer = THMTrainer(api_key="xai-...", openvpn_iface="tun0")
  await trainer.run_box(
      box_name   = "Blue",
      target_ip  = "10.10.10.40",
      difficulty = "easy",
      category   = "windows",
  )
"""

import asyncio
import re
import json
import subprocess
import logging
import httpx
from datetime import datetime
from pathlib import Path
from typing import Optional, Callable
from openai import AsyncOpenAI

from orchestrator.hive_orchestrator import HiveOrchestrator
from memory.memory_manager import MemoryManager

logger = logging.getLogger(__name__)

# Known flag formats across platforms
FLAG_PATTERNS = [
    r'THM\{[^}]+\}',
    r'HTB\{[^}]+\}',
    r'flag\{[^}]+\}',
    r'FLAG\{[^}]+\}',
    r'user\.txt[:\s]+([a-f0-9]{32})',
    r'root\.txt[:\s]+([a-f0-9]{32})',
    r'[a-f0-9]{32}',   # generic MD5 flag
]

THM_BOX_TYPES = {
    "linux":   ["ReconAgent","FingerprintAgent","ExploitAgent","ValidateAgent","PivotAgent","ReportAgent"],
    "windows": ["ReconAgent","FingerprintAgent","ExploitAgent","ValidateAgent","PivotAgent","ReportAgent"],
    "web":     ["ReconAgent","FingerprintAgent","ExploitAgent","ValidateAgent","ReportAgent"],
    "network": ["ReconAgent","FingerprintAgent","ValidateAgent","ReportAgent"],
    "crypto":  ["ReconAgent","ReportAgent"],
}


class THMTrainer:
    """
    Runs HiveReaper against THM/HTB boxes with full learning capture.
    """

    def __init__(
        self,
        api_key:         str,
        on_log:          Callable[[str, str], None] = None,
        on_finding:      Callable[[dict], None]     = None,
        on_flag:         Callable[[str], None]      = None,
        on_lane_update:  Callable                   = None,
        on_commander:    Callable[[str], None]      = None,
        on_complete:     Callable[[], None]         = None,
        openvpn_iface:   str                        = "tun0",
    ):
        self.api_key        = api_key
        self._log_cb        = on_log        or (lambda m, l: print(f"[{l.upper()}] {m}"))
        self._find_cb       = on_finding    or (lambda f: None)
        self._flag_cb       = on_flag       or (lambda f: print(f"🚩 FLAG: {f}"))
        self._lane_cb       = on_lane_update or (lambda *a: None)
        self._cmd_cb        = on_commander  or (lambda t: None)
        self._complete_cb   = on_complete   or (lambda: None)
        self.openvpn_iface  = openvpn_iface

        self._client        = AsyncOpenAI(
            api_key=api_key,
            base_url="https://api.x.ai/v1",
            timeout=httpx.Timeout(connect=30.0, read=120.0, write=30.0, pool=10.0),
            max_retries=0,
        )
        self._memory        = MemoryManager(self._client, self._log_cb)
        self._flags_found:  list[str] = []
        self._current_box:  dict      = {}
        self._aborted:      bool      = False

    # ── Main entry point ──────────────────────────────────────────────────────

    async def run_box(
        self,
        box_name:   str,
        target_ip:  str,
        difficulty: str = "medium",
        category:   str = "linux",
        hint:       str = "",
        objective:  str = "",
    ) -> dict:
        """
        Run the full swarm against a THM box. Returns training result dict.
        """
        self._flags_found = []
        self._aborted     = False
        self._current_box = {
            "box_name":   box_name,
            "target_ip":  target_ip,
            "difficulty": difficulty,
            "category":   category,
            "start_time": datetime.now(),
        }

        obj = objective or (
            f"CTF — TryHackMe box '{box_name}' ({difficulty} {category}). "
            f"Find user.txt and root.txt flags. "
            + (f"Hint: {hint}" if hint else "")
        )

        self._log(f"[THM Trainer] Starting box: {box_name} ({target_ip})", "info")
        self._log(f"[THM Trainer] Category: {category}  Difficulty: {difficulty}", "info")

        # Check VPN connectivity
        vpn_ok = await self._check_vpn(target_ip)
        if not vpn_ok:
            self._log(
                f"[THM Trainer] WARNING: {target_ip} unreachable via {self.openvpn_iface} — "
                f"make sure you are connected to the THM VPN (sudo openvpn <your.ovpn>). "
                f"Continuing anyway — tools will fail gracefully if target is down.",
                "warning",
            )
        else:
            self._log(f"[THM Trainer] VPN OK — {target_ip} is reachable, proceeding.", "success")

        # Start memory episode
        import uuid
        campaign_id = f"thm-{box_name.lower().replace(' ','-')}-{uuid.uuid4().hex[:6]}"
        self._memory.start_episode(
            campaign_id = campaign_id,
            target      = target_ip,
            objective   = obj,
            opsec_mode  = "normal",
            source      = "thm",
        )

        # Build memory context from past experience
        mem_context = await self._memory.build_context_prompt(
            target      = target_ip,
            objective   = obj,
            target_type = f"ctf_{category}",
        )

        # Create orchestrator with memory-enhanced callbacks
        orchestrator = HiveOrchestrator(
            api_key         = self.api_key,
            on_log          = self._on_log,
            on_lane_update  = self._lane_cb,
            on_finding      = self._on_finding,
            on_commander    = self._on_commander,
            on_complete     = self._on_complete,
        )

        # Inject memory context into orchestrator
        orchestrator._memory_context = mem_context
        orchestrator._training_mode  = True

        # Keep a live reference so give_hint() can reach the running orchestrator
        self._orchestrator = orchestrator

        # Run the campaign
        try:
            await orchestrator.run_campaign(
                campaign_id = campaign_id,
                target      = target_ip,
                objective   = obj,
                opsec_mode  = "normal",
                max_lanes   = 3,
            )
        except Exception as e:
            self._log(f"[THM Trainer] Campaign error: {e}", "error")

        # Close episode and learn
        duration = int((datetime.now() - self._current_box["start_time"]).total_seconds())
        outcome  = "success" if self._flags_found else "partial" if self._memory._current_episode.get("findings") else "failed"

        self._log(
            f"[THM Trainer] Box complete — outcome: {outcome}  "
            f"flags: {self._flags_found}  duration: {duration//60}m",
            "success" if outcome == "success" else "warning",
        )

        eid = await self._memory.close_episode(
            outcome     = outcome,
            target_type = f"ctf_{category}",
            tags        = [
                "ctf", "thm", category, difficulty, box_name.lower().replace(" ","_"),
            ] + (["rooted"] if len(self._flags_found) >= 2 else ["partial"]),
        )

        result = {
            "episode_id":   eid,
            "box_name":     box_name,
            "target_ip":    target_ip,
            "outcome":      outcome,
            "flags_found":  self._flags_found,
            "duration_secs": duration,
            "category":     category,
            "difficulty":   difficulty,
        }

        self._complete_cb()
        return result

    # ── Hint injection ────────────────────────────────────────────────────────

    def give_hint(self, hint_text: str):
        """
        Live-inject a hint into the running swarm AND record it to memory.
        The hint is immediately available to the next agent that runs in any lane.
        Grok will interpret it and broadcast a tactical directive to all lanes.
        """
        self._log(f"[THM Trainer] Operator hint: {hint_text}", "info")
        self._memory.record_hint(hint_text, context="operator_manual")

        # Push into the live orchestrator so the NEXT agent to run sees it
        if hasattr(self, "_orchestrator") and self._orchestrator:
            self._orchestrator.inject_hint(hint_text)
        else:
            self._log("[THM Trainer] No live orchestrator — hint saved to memory only", "warning")

    def mark_flag(self, flag: str):
        """Manually register a flag if the swarm missed it."""
        if flag not in self._flags_found:
            self._flags_found.append(flag)
            self._memory._current_episode.setdefault("flags_found", []).append(flag)
            self._flag_cb(flag)
            self._log(f"[THM Trainer] Flag manually recorded: {flag}", "success")

    # ── Callbacks ─────────────────────────────────────────────────────────────

    def _on_log(self, message: str, level: str):
        self._memory.record_step(message[:120])
        # Detect tool names
        for tool in ("nmap","nuclei","sqlmap","ffuf","hydra","crackmapexec",
                     "impacket","enum4linux","nikto","whatweb","searchsploit"):
            if tool in message.lower():
                self._memory.record_tool(tool)
        self._log_cb(message, level)

    def _on_finding(self, finding: dict):
        self._memory.record_finding(finding)
        # Detect flags in finding content
        for field in ("title", "detail"):
            text = finding.get(field, "")
            for pat in FLAG_PATTERNS:
                matches = re.findall(pat, text, re.IGNORECASE)
                for m in matches:
                    flag = m if m.startswith(("THM{","HTB{","flag{","FLAG{")) else f"[hash] {m}"
                    if flag not in self._flags_found:
                        self._flags_found.append(flag)
                        self._flag_cb(flag)
                        self._log(f"[THM Trainer] 🚩 FLAG CAPTURED: {flag}", "success")
        self._find_cb(finding)

    def _on_commander(self, text: str):
        self._cmd_cb(text)

    def _on_complete(self):
        pass  # handled in run_box

    def _log(self, message: str, level: str = "info"):
        self._log_cb(message, level)

    # ── VPN check ─────────────────────────────────────────────────────────────

    async def _check_vpn(self, target_ip: str) -> bool:
        """Ping the target once to confirm VPN connectivity."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "ping", "-c", "1", "-W", "3", target_ip,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.wait(), timeout=5)
            reachable = proc.returncode == 0
            self._log(
                f"[THM Trainer] VPN connectivity: {'OK' if reachable else 'UNREACHABLE'}",
                "success" if reachable else "warning",
            )
            return reachable
        except Exception:
            return False
