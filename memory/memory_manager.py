"""
HiveReaper v2 — Memory Manager
Sits between the orchestrator and the experience store.

Responsibilities:
  1. Before campaign  — retrieve relevant context, inject into Grok prompts
  2. During campaign  — match live tool output against known patterns in real-time
  3. After campaign   — extract lessons, patterns, and strategies via Grok
  4. Training mode    — record THM/HTB episodes with full attack paths
"""

import json
import logging
from datetime import datetime
from typing import Optional, Callable
from openai import AsyncOpenAI

from memory.experience_store import ExperienceStore

logger = logging.getLogger(__name__)
GROK_MODEL = "grok-3"


class MemoryManager:

    def __init__(self, grok_client: AsyncOpenAI, on_log: Callable[[str, str], None]):
        self.client  = grok_client
        self._log    = lambda msg, lvl="info": on_log(msg, lvl)
        self.store   = ExperienceStore()
        self._current_episode: dict = {}

    # ── Pre-campaign: context retrieval ──────────────────────────────────────

    async def build_context_prompt(
        self, target: str, objective: str = "", target_type: str = None
    ) -> str:
        """
        Build a memory context block to inject at the top of the
        orchestrator's attack plan prompt. Returns formatted string.
        """
        self._log("[Memory] Retrieving relevant past experience…", "info")

        episodes = self.store.get_similar_episodes(
            target=target,
            target_type=target_type,
            limit=5,
        )
        patterns = self.store.get_all_patterns()
        best_strat = self.store.get_best_strategy(target_type or "unknown")
        stats = self.store.get_stats()

        if not episodes and not patterns:
            self._log("[Memory] No prior experience found — starting fresh.", "info")
            return ""

        self._log(
            f"[Memory] Loaded {len(episodes)} episodes, "
            f"{len(patterns)} patterns, "
            f"{stats.get('episodes',0)} total in store.",
            "success",
        )

        # Build episode summaries
        ep_lines = []
        for ep in episodes:
            flags = json.loads(ep.get("flags_found", "[]"))
            tags  = json.loads(ep.get("tags", "[]"))
            path  = json.loads(ep.get("attack_path", "[]"))
            ep_lines.append(
                f"  • [{ep.get('source','?').upper()}] {ep.get('target','')} "
                f"({ep.get('target_type','?')}) — outcome: {ep.get('outcome','?')} "
                f"— tags: {', '.join(tags[:6])} "
                f"— lessons: {ep.get('lessons','none')[:120]}"
                + (f"\n    Attack path: {' → '.join(str(s) for s in path[:8])}" if path else "")
                + (f"\n    Flags: {flags}" if flags else "")
            )

        # Build pattern summaries (top 30 by success count)
        pat_lines = []
        for p in sorted(patterns, key=lambda x: x.get("success_count", 0), reverse=True)[:30]:
            pat_lines.append(
                f"  • Signal: \"{p.get('signal','')}\" "
                f"→ Action: {p.get('action','')} "
                f"[confirmed {p.get('success_count',1)}x]"
                + (f" [{p.get('cve_id','')}]" if p.get("cve_id") else "")
            )

        # Best strategy
        strat_block = ""
        if best_strat:
            seq = json.loads(best_strat.get("agent_sequence", "[]"))
            strat_block = (
                f"\nBest known strategy for {best_strat.get('target_type','')} targets:\n"
                f"  Agent sequence: {' → '.join(seq)}\n"
                f"  Success rate: {best_strat.get('success_rate',0):.0%}  "
                f"Avg duration: {best_strat.get('avg_duration',0)//60}m\n"
            )

        context = f"""
=== HIVEREAPER MEMORY CONTEXT ===
You have prior experience from {stats.get('episodes',0)} campaigns
({stats.get('thm_boxes',0)} THM/CTF boxes, {stats.get('live_engagements',0)} live engagements).
{stats.get('patterns',0)} attack patterns learned. {stats.get('successes',0)} successes recorded.

RELEVANT PAST EPISODES:
{chr(10).join(ep_lines) if ep_lines else "  None matching this target yet."}

LEARNED ATTACK PATTERNS (fire these automatically when signals are detected):
{chr(10).join(pat_lines) if pat_lines else "  No patterns yet."}
{strat_block}
Use this memory to:
1. Prioritise attack vectors that worked before on similar targets
2. Skip approaches that consistently failed
3. Fire pattern-matched actions immediately when signals are seen
4. Adapt the agent sequence based on the best known strategy
=== END MEMORY CONTEXT ===
"""
        return context

    # ── During campaign: real-time pattern matching ───────────────────────────

    def match_patterns(self, tool_output: str) -> list[dict]:
        """
        Called by agents after each tool run.
        Returns matching patterns as hints to inject into the agent prompt.
        """
        matched = self.store.get_patterns_for_context(tool_output)
        if matched:
            self._log(
                f"[Memory] {len(matched)} pattern(s) matched in tool output — "
                f"injecting into agent context",
                "success",
            )
        return matched

    def format_pattern_hints(self, patterns: list[dict]) -> str:
        """Format matched patterns as a hint block for agent prompts."""
        if not patterns:
            return ""
        lines = ["\n=== MEMORY PATTERN ALERTS — ACT ON THESE ==="]
        for p in patterns:
            lines.append(
                f"  ⚡ SIGNAL DETECTED: \"{p['signal']}\" "
                f"→ {p['action']}"
                + (f" (CVE: {p['cve_id']})" if p.get("cve_id") else "")
                + f" [confirmed {p.get('success_count',1)}x in past campaigns]"
            )
        lines.append("=== END PATTERN ALERTS ===\n")
        return "\n".join(lines)

    # ── Episode lifecycle ─────────────────────────────────────────────────────

    def start_episode(
        self, campaign_id: str, target: str, objective: str,
        opsec_mode: str, source: str = "live"
    ):
        self._current_episode = {
            "campaign_id":   campaign_id,
            "target":        target,
            "objective":     objective,
            "opsec_mode":    opsec_mode,
            "source":        source,
            "start_time":    datetime.now(),
            "timestamp":     datetime.now().isoformat(),
            "findings":      [],
            "attack_path":   [],
            "tools_used":    [],
            "flags_found":   [],
            "tags":          [],
            "outcome":       "unknown",
        }
        self._log(f"[Memory] Episode started — source: {source.upper()}", "info")

    def record_step(self, step: str):
        """Record a step in the attack path (e.g. 'ReconAgent found 3 open ports')."""
        self._current_episode.get("attack_path", []).append({
            "time": datetime.now().isoformat(),
            "step": step,
        })

    def record_tool(self, tool_name: str):
        tools = self._current_episode.get("tools_used", [])
        if tool_name not in tools:
            tools.append(tool_name)

    def record_finding(self, finding: dict):
        self._current_episode.get("findings", []).append({
            "title":        finding.get("title", ""),
            "severity":     finding.get("severity", "info"),
            "finding_type": finding.get("finding_type", ""),
            "target":       finding.get("target", ""),
        })
        # Auto-detect flags
        title = finding.get("title", "").lower()
        detail = finding.get("detail", "").lower()
        if "flag{" in detail or "thm{" in detail or "htb{" in detail or "flag" in title:
            raw = finding.get("detail", "")
            import re
            flags = re.findall(r'(?:flag|thm|htb|user|root)\{[^}]+\}', raw, re.IGNORECASE)
            self._current_episode["flags_found"].extend(flags)
            if flags:
                self._log(f"[Memory] FLAG DETECTED: {flags}", "success")

    def record_hint(self, hint_text: str, context: str = ""):
        """Called when the operator manually provides a hint during training."""
        eid = self._current_episode.get("campaign_id", "unknown")
        self.store.save_hint(eid, hint_text, context)
        self._current_episode.get("attack_path", []).append({
            "time": datetime.now().isoformat(),
            "step": f"HINT: {hint_text}",
        })
        self._log(f"[Memory] Hint recorded: {hint_text[:80]}", "info")

    async def close_episode(
        self, outcome: str = "unknown",
        target_type: str = "unknown",
        tags: list[str] = None,
    ) -> str:
        """
        Called when a campaign completes.
        Runs Grok retrospective to extract lessons + patterns, then saves.
        Returns episode ID.
        """
        ep = self._current_episode
        if not ep:
            return ""

        start = ep.get("start_time")
        duration = int((datetime.now() - start).total_seconds()) if start else 0

        ep["outcome"]       = outcome
        ep["target_type"]   = target_type
        ep["duration_secs"] = duration
        ep["tags"]          = tags or []

        self._log("[Memory] Running Grok retrospective…", "info")

        # Extract lessons and patterns via Grok
        lessons, patterns, strategy = await self._grok_retrospective(ep)

        ep["lessons"] = lessons

        # Save patterns
        for pat in patterns:
            self.store.save_pattern(pat)
        self._log(f"[Memory] {len(patterns)} new patterns extracted and saved.", "success")

        # Save strategy
        if ep.get("attack_path"):
            agent_seq = list(dict.fromkeys(
                s.get("step","").split(" ")[0]
                for s in ep["attack_path"]
                if "Agent" in s.get("step","")
            ))
            self.store.save_strategy({
                "target_type":    target_type,
                "agent_sequence": agent_seq,
                "duration_secs":  duration,
                "success":        outcome == "success",
                "notes":          lessons[:200],
            })

        # Save episode
        eid = self.store.save_episode(ep)
        self._log(
            f"[Memory] Episode saved — id: {eid}  outcome: {outcome}  "
            f"duration: {duration//60}m{duration%60}s  "
            f"flags: {ep.get('flags_found',[])}",
            "success",
        )
        return eid

    # ── Grok retrospective ────────────────────────────────────────────────────

    async def _grok_retrospective(self, ep: dict) -> tuple[str, list[dict], dict]:
        """
        Ask Grok to analyse the completed campaign and extract:
          - lessons learned
          - reusable attack patterns
          - strategy assessment
        """
        findings_summary = json.dumps(ep.get("findings", [])[:20], indent=2)
        attack_path      = json.dumps(ep.get("attack_path", [])[:30], indent=2)
        flags            = ep.get("flags_found", [])

        prompt = f"""
You are analysing a completed HiveReaper pentest campaign for learning.

Campaign details:
  Target:     {ep.get('target','')}
  Target type: {ep.get('target_type','')}
  Objective:  {ep.get('objective','')}
  Outcome:    {ep.get('outcome','')}
  Duration:   {ep.get('duration_secs',0)//60} minutes
  Source:     {ep.get('source','')}
  Flags found: {flags}

Attack path taken:
{attack_path}

Findings:
{findings_summary}

Extract maximum learning value. Return JSON:
{{
  "lessons": "<2-3 sentences: what worked, what didn't, what to do differently next time>",
  "target_type": "<web|ad|ctf_linux|ctf_windows|network|api — classify this target>",
  "tags": ["<tag1>", "<tag2>", ...],  // e.g. apache, sqli, thm, linux, privesc, suid
  "patterns": [
    {{
      "signal":           "<exact string to watch for in tool output>",
      "signal_type":      "version|port|service|header|response|banner",
      "action":           "<specific action to take immediately when this signal is seen>",
      "finding_type":     "<what kind of finding this leads to>",
      "cve_id":           "<CVE-ID or null>",
      "tags":             ["<tag>"],
      "example_evidence": "<quote from this campaign that triggered this pattern>"
    }}
  ],
  "winning_moves": ["<key decision that led toward success>"],
  "wasted_time":   ["<what to skip next time on similar targets>"]
}}

Focus on SPECIFIC, ACTIONABLE patterns — exact version strings, exact port numbers,
exact response patterns. Vague patterns are useless.
Examples of GOOD patterns:
  signal: "Apache/2.4.49", action: "Test CVE-2021-41773 path traversal immediately"
  signal: "X-Powered-By: PHP/5.6", action: "Check for PHP object injection, outdated PHP CVEs"
  signal: "port 2049 open", action: "Run showmount -e to enumerate NFS exports"
  signal: "SUID /usr/bin/find", action: "Run find . -exec /bin/sh -p ; for privesc"
"""

        for attempt in range(3):
            try:
                response = await self.client.chat.completions.create(
                    model=GROK_MODEL,
                    messages=[
                        {"role": "system", "content":
                         "You are a security research AI extracting learning from pentest data. "
                         "Return only valid JSON."},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.1,
                    max_tokens=2500,
                )
                raw = response.choices[0].message.content.strip()
                if raw.startswith("```"):
                    raw = raw.split("```")[1]
                    if raw.startswith("json"):
                        raw = raw[4:]
                data = json.loads(raw)

                # Update episode tags and target_type from Grok's assessment
                self._current_episode["tags"]        = data.get("tags", [])
                self._current_episode["target_type"] = data.get("target_type", "unknown")

                return (
                    data.get("lessons", ""),
                    data.get("patterns", []),
                    data.get("winning_moves", []),
                )
            except Exception as e:
                if attempt < 2:
                    wait = 15 * (attempt + 1)
                    self._log(f"[Memory] Retrospective error (attempt {attempt+1}/3) — retrying in {wait}s", "warning")
                    await asyncio.sleep(wait)
                else:
                    logger.exception("Grok retrospective failed after 3 attempts")
                    self._log(f"[Memory] Retrospective failed: {e}", "error")
                    return ("Retrospective failed.", [], [])
