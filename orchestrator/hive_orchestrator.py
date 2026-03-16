"""
HiveReaper v2 — Hive Orchestrator
Powered by xAI Grok. Coordinates all pentest agents in a swarm.

The orchestrator:
  1. Receives the campaign objective + target
  2. Calls Grok to generate an attack plan with lane assignments
  3. Spawns agents into lanes and routes findings back
  4. Dynamically re-plans based on new intelligence
  5. Manages OpSec budget across all lanes
"""

import json
import asyncio
import logging
from datetime import datetime
from typing import Optional, Callable
import httpx
from openai import AsyncOpenAI  # xAI Grok uses OpenAI-compatible API

from agents.recon_agent       import ReconAgent
from agents.fingerprint_agent import FingerprintAgent
from agents.exploit_agent     import ExploitAgent
from agents.mail_agent        import MailAgent
from agents.validate_agent    import ValidateAgent
from agents.pivot_agent       import PivotAgent
from agents.report_agent      import ReportAgent
from memory.memory_manager    import MemoryManager

logger = logging.getLogger(__name__)

GROK_BASE_URL = "https://api.x.ai/v1"
GROK_MODEL    = "grok-3"

AGENT_REGISTRY = {
    "ReconAgent":       ReconAgent,
    "FingerprintAgent": FingerprintAgent,
    "ExploitAgent":     ExploitAgent,
    "MailAgent":        MailAgent,
    "ValidateAgent":    ValidateAgent,
    "PivotAgent":       PivotAgent,
    "ReportAgent":      ReportAgent,
}

ORCHESTRATOR_SYSTEM = """You are the HiveReaper Hive Orchestrator — an elite autonomous red-team AI commander powered by Grok.

Your role:
- Analyse the target and campaign objective
- Generate a structured attack plan divided into parallel lanes
- Each lane has a sequence of agents to run
- Dynamically adapt the plan based on new findings from agents
- Track OpSec budget (100 = clean, 0 = burned)
- Summarise intelligence and brief agents

Available agents:
  ReconAgent       – passive + active recon (DNS, port scan, OSINT)
  FingerprintAgent – service/OS/tech fingerprinting
  ExploitAgent     – vulnerability testing and exploitation (web, CVE, FTP)
  MailAgent        – mail service exploitation: SMTP user enum, open relay,
                     IMAP/POP3 credential spray, Exim/Dovecot CVE probes
                     (use when ports 25/465/587/110/143/993/995 are open)
  ValidateAgent    – confirms findings, deduplicates, rates severity  
  PivotAgent       – lateral movement, credential reuse, network pivoting
  ReportAgent      – structures and writes the final pentest report

OpSec modes:
  ghost   – passive only, no active probes
  stealth – low-and-slow, randomised timing
  normal  – standard pentesting cadence
  loud    – speed over stealth, IDS noise acceptable

Respond ONLY with valid JSON in the schema provided. No prose outside the JSON."""


class HiveOrchestrator:
    """
    Central Grok-powered commander.
    All UI callbacks are thread-safe Qt signals passed in at construction.
    """

    def __init__(
        self,
        api_key: str,
        on_log:        Callable[[str, str], None],
        on_lane_update: Callable[[str, str, str, int, int], None],
        on_finding:    Callable[[dict], None],
        on_commander:  Callable[[str], None],
        on_complete:   Callable[[], None],
    ):
        self.api_key        = api_key
        self.on_log         = on_log
        self.on_lane_update = on_lane_update
        self.on_finding     = on_finding
        self.on_commander   = on_commander
        self.on_complete    = on_complete

        self._client: Optional[AsyncOpenAI] = None
        self._campaign_id: Optional[str]    = None
        self._target: str                   = ""
        self._objective: str                = ""
        self._opsec_mode: str               = "stealth"
        self._opsec_budget: int             = 100
        self._aborted: bool                 = False
        self._lanes: dict                   = {}   # lane_id → lane dict
        self._all_findings: list            = []
        self._active_tasks: list            = []
        self._memory: Optional[MemoryManager] = None
        self._memory_context: str             = ""
        self._training_mode: bool             = False
        self._live_hints: list[str]           = []   # operator hints injected in real-time
        self._campaign_context: dict          = {}   # accumulated findings shared across all lanes

    # ── Public API ────────────────────────────────────────────────────────────

    async def run_campaign(
        self,
        campaign_id: str,
        target: str,
        objective: str,
        opsec_mode: str = "stealth",
        max_lanes: int  = 5,
    ):
        self._campaign_id   = campaign_id
        self._target        = target
        self._objective     = objective
        self._opsec_mode    = opsec_mode
        self._opsec_budget  = 100
        self._aborted       = False
        self._all_findings  = []

        self._client = AsyncOpenAI(
            api_key=self.api_key,
            base_url=GROK_BASE_URL,
            timeout=httpx.Timeout(
                connect=30.0,   # TCP connect — was defaulting to 5s
                read=120.0,     # response stream
                write=30.0,
                pool=10.0,
            ),
            max_retries=0,      # we handle retries ourselves for better logging
        )

        # Initialise memory manager (only if not already set by training mode)
        if not self._memory:
            self._memory = MemoryManager(self._client, self.on_log)

        # Start tracking this episode
        self._memory.start_episode(
            campaign_id = campaign_id,
            target      = target,
            objective   = objective,
            opsec_mode  = opsec_mode,
            source      = "live",
        )

        # Build memory context from past experience
        if not self._memory_context:
            self._memory_context = await self._memory.build_context_prompt(
                target      = target,
                objective   = objective,
                target_type = None,
            )

        # Reset shared campaign context for this run
        self._campaign_context = {
            "target":    target,
            "objective": objective,
            "findings":  [],
            "hosts_discovered": [],
            "web_targets": [],
            "tech_stack": {},
            "potential_cves": [],
            "exploit_targets": [],
            "vulnerabilities_confirmed": [],
            "credentials_found": [],
            "pivot_candidates": [],
            "shells_obtained": [],
            "validated_findings": [],
            "operator_hints": [],
        }
        self._log(f"[Commander] Hive Orchestrator online — target: {target}", "info")
        self._log(f"[Commander] Objective: {objective}", "info")
        self._log(f"[Commander] OpSec mode: {opsec_mode.upper()}", "info")

        try:
            plan = await self._generate_attack_plan(target, objective, opsec_mode, max_lanes)
            self._log_commander(f"Attack plan generated — {len(plan['lanes'])} lanes\n{plan['summary']}")

            await self._execute_plan(plan)

            if not self._aborted:
                self._log("[Commander] All lanes complete — generating final report.", "success")
                await self._generate_final_report()

        except asyncio.CancelledError:
            self._log("[Commander] Campaign cancelled.", "warning")
        except Exception as e:
            self._log(f"[Commander] Fatal orchestrator error: {e}", "error")
            logger.exception("Orchestrator error")
        finally:
            # Save episode to memory
            if self._memory:
                outcome = "success" if self._all_findings else "failed"
                crits = sum(1 for f in self._all_findings if f.get("severity") in ("critical","high"))
                if crits > 0:
                    outcome = "success"
                try:
                    eid = await self._memory.close_episode(
                        outcome     = outcome,
                        target_type = "unknown",
                        tags        = [],
                    )
                    self._log(f"[Commander] Episode saved to memory — id: {eid}", "success")
                except Exception as me:
                    self._log(f"[Commander] Memory save failed: {me}", "warning")
            self.on_complete()

    def abort(self):
        self._aborted = True
        for task in self._active_tasks:
            task.cancel()
        self._log("[Commander] Abort signal received — cancelling all lanes.", "warning")

    def inject_hint(self, hint_text: str):
        """
        Called by THMTrainer.give_hint() to push a hint into the live swarm.
        The hint is prepended to prior_context for the NEXT agent that runs
        in any lane, so it acts on it immediately.
        """
        self._live_hints.append(hint_text)
        self._log(
            f"[Commander] 💡 Hint injected into swarm: {hint_text[:100]}",
            "warning",
        )
        # Ask Grok to interpret the hint and broadcast to lanes
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                asyncio.ensure_future(self._broadcast_hint(hint_text))
        except Exception:
            pass

    async def _broadcast_hint(self, hint_text: str):
        """Send hint to Grok for interpretation, then log the tactical update."""
        try:
            directive = await self._grok_call(
                messages=[
                    {"role": "system", "content":
                     "You are a red-team commander receiving a tactical hint mid-operation. "
                     "Interpret it and give a 1-2 sentence actionable directive to the agents. "
                     "Be specific — name tools and commands if possible. Return plain text only."},
                    {"role": "user", "content":
                     f"Current target: {self._target}\n"
                     f"Operator hint: {hint_text}\n"
                     f"What should the agents do right now?"},
                ],
                temperature=0.2,
                max_tokens=200,
                label="hint broadcast",
            )
            self._log(f"[Commander] Tactical update: {directive}", "info")
            self.on_commander(f"💡 OPERATOR HINT RECEIVED\n{hint_text}\n\nTactical directive: {directive}")
        except Exception as e:
            self._log(f"[Commander] Hint broadcast failed: {e}", "warning")

    # ── Grok plan generation ──────────────────────────────────────────────────

    async def _grok_call(self, messages: list, temperature: float = 0.2,
                         max_tokens: int = 2000, label: str = "Grok") -> str:
        """Retry wrapper for all orchestrator Grok calls.
        Returns the raw text content string, or raises on final failure.
        """
        for attempt in range(3):
            try:
                response = await self._client.chat.completions.create(
                    model=GROK_MODEL,
                    messages=messages,
                    temperature=temperature,
                    max_tokens=max_tokens,
                )
                return response.choices[0].message.content.strip()
            except Exception as e:
                if attempt < 2:
                    wait = 15 * (attempt + 1)
                    self._log(
                        f"[Commander] {label} error (attempt {attempt + 1}/3): "
                        f"{type(e).__name__} — retrying in {wait}s",
                        "warning",
                    )
                    await asyncio.sleep(wait)
                else:
                    raise

    async def _generate_attack_plan(
        self, target: str, objective: str, opsec_mode: str, max_lanes: int
    ) -> dict:
        self._log("[Commander] Consulting Grok for attack plan…", "info")

        # Inject memory context into plan prompt
        memory_block = self._memory_context or ""
        prompt = f"""
{memory_block}

Generate an autonomous red-team attack plan for this engagement:

Target: {target}
Objective: {objective}
OpSec Mode: {opsec_mode}
Max Parallel Lanes: {max_lanes}

Return ONLY a JSON object matching this schema:
{{
  "summary": "<2-3 sentence engagement overview>",
  "lanes": [
    {{
      "id": "lane-<n>",
      "label": "<short lane purpose>",
      "priority": <1-5>,
      "agents": ["<AgentName>", ...],
      "target_scope": "<specific sub-target or 'full'>",
      "objective": "<lane-specific goal>",
      "opsec_cost": <estimated % opsec budget this lane consumes>
    }}
  ],
  "initial_briefing": "<tactical briefing the commander narrates to the team>"
}}

Rules:
- Always start with ReconAgent in at least one lane
- ExploitAgent must come after FingerprintAgent in the same lane or a dependent lane  
- ValidateAgent should verify all findings before reporting
- ReportAgent is the final agent in the last lane
- Keep total opsec_cost across all lanes under 100
- In ghost mode, omit ExploitAgent and PivotAgent
- Max {max_lanes} lanes
"""

        raw = await self._grok_call(
            messages=[
                {"role": "system", "content": ORCHESTRATOR_SYSTEM},
                {"role": "user",   "content": prompt},
            ],
            temperature=0.3,
            max_tokens=2000,
            label="attack plan",
        )
        # Strip markdown fences if present
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        plan = json.loads(raw)
        return plan

    # ── Plan execution ────────────────────────────────────────────────────────

    async def _execute_plan(self, plan: dict):
        self._log_commander(plan.get("initial_briefing", ""))

        # Group lanes by priority — higher priority run first, same priority parallel
        by_priority: dict[int, list] = {}
        for lane in plan["lanes"]:
            p = lane.get("priority", 3)
            by_priority.setdefault(p, []).append(lane)

        for priority in sorted(by_priority.keys()):
            if self._aborted:
                break
            group = by_priority[priority]
            self._log(f"[Commander] Launching priority-{priority} lanes ({len(group)} lanes)…", "info")

            tasks = [
                asyncio.create_task(self._run_lane(lane))
                for lane in group
            ]
            self._active_tasks.extend(tasks)
            results = await asyncio.gather(*tasks, return_exceptions=True)
            self._active_tasks = [t for t in self._active_tasks if not t.done()]

            for lane, result in zip(group, results):
                if isinstance(result, Exception):
                    self._log(f"[Commander] Lane {lane['id']} failed: {result}", "error")

            # Re-plan if significant findings emerged
            if len(self._all_findings) > 0 and priority < max(by_priority.keys()):
                await self._replan_if_needed(plan, priority)

    async def _run_lane(self, lane: dict):
        lane_id   = lane["id"]
        agents    = lane.get("agents", [])
        scope     = lane.get("target_scope", self._target)
        objective = lane.get("objective", self._objective)

        self._lanes[lane_id] = {
            "id":      lane_id,
            "status":  "active",
            "agents":  agents,
            "current": None,
            "findings": [],
        }

        self.on_lane_update(lane_id, "PLANNING", agents[0] if agents else "", 0, self._opsec_budget)
        self._log(f"[Commander] Lane {lane_id} online — agents: {' → '.join(agents)}", "info")

        previous_output = {}

        for i, agent_name in enumerate(agents):
            if self._aborted:
                break

            AgentClass = AGENT_REGISTRY.get(agent_name)
            if not AgentClass:
                self._log(f"Unknown agent: {agent_name}", "error")
                continue

            self._lanes[lane_id]["current"] = agent_name
            progress = int((i / len(agents)) * 100)
            self.on_lane_update(lane_id, "EXECUTING", agent_name, progress, self._opsec_budget)

            try:
                # Build full context: campaign-wide accumulated data + lane-local output + hints
                context_with_hints = {**self._campaign_context, **previous_output}
                if self._live_hints:
                    context_with_hints["operator_hints"] = list(self._live_hints)
                    self._log(
                        f"[{lane_id}] Injecting {len(self._live_hints)} hint(s) + "
                        f"{len(self._campaign_context.get('findings',[]))} campaign findings into {agent_name}",
                        "info",
                    )
                else:
                    n_finds = len(self._campaign_context.get("findings", []))
                    n_hosts = len(self._campaign_context.get("hosts_discovered", []))
                    if n_finds > 0 or n_hosts > 0:
                        self._log(
                            f"[{lane_id}] {agent_name} context: "
                            f"{n_hosts} hosts, {n_finds} findings from campaign so far",
                            "info",
                        )

                agent = AgentClass(
                    lane_id       = lane_id,
                    target        = scope if scope != "full" else self._target,
                    objective     = objective,
                    opsec_mode    = self._opsec_mode,
                    prior_context = context_with_hints,
                    on_log        = self.on_log,
                    on_finding    = self._handle_finding,
                    grok_client   = self._client,
                )

                result = await agent.run()
                previous_output = result

                # Merge result into the shared campaign context so later lanes
                # and higher-priority agents always have the full picture
                self._merge_campaign_context(result)

                self._opsec_budget = max(0, self._opsec_budget - result.get("opsec_cost", 0))

                self.on_lane_update(lane_id, "EXECUTING", agent_name, progress + 5, self._opsec_budget)
                self._log(f"[{lane_id}] {agent_name} complete — opsec budget: {self._opsec_budget}%", "success")

            except Exception as e:
                self._log(f"[{lane_id}] {agent_name} error: {e}", "error")
                self.on_lane_update(lane_id, "ERROR", agent_name, progress, self._opsec_budget)
                logger.exception(f"Agent {agent_name} error in lane {lane_id}")

        self.on_lane_update(lane_id, "COMPLETE", agents[-1] if agents else "", 100, self._opsec_budget)
        self._lanes[lane_id]["status"] = "complete"
        self._log(f"[Commander] Lane {lane_id} complete.", "success")

    # ── Dynamic re-planning ───────────────────────────────────────────────────

    async def _replan_if_needed(self, plan: dict, completed_priority: int):
        critical = [f for f in self._all_findings if f.get("severity") in ("critical", "high")]
        if not critical:
            return

        self._log(f"[Commander] {len(critical)} high/critical findings — consulting Grok for tactical update…", "warning")

        finding_summary = "\n".join(
            f"- [{f['severity'].upper()}] {f.get('title','')} on {f.get('target','')}"
            for f in critical[:10]
        )

        prompt = f"""
You are mid-engagement. New critical findings have emerged:

{finding_summary}

Original target: {self._target}
Current OpSec budget: {self._opsec_budget}%
Remaining priorities: {[p for p in plan.get('_all_priorities', []) if p > completed_priority]}

Should we adjust the remaining attack plan? If yes, return a JSON object:
{{
  "adjust": true,
  "commentary": "<tactical commentary>",
  "new_lanes": [ ... ]  // same schema as original lanes
}}
If no adjustment needed:
{{
  "adjust": false,
  "commentary": "<why no change>"
}}
"""
        try:
            raw = await self._grok_call(
                messages=[
                    {"role": "system", "content": ORCHESTRATOR_SYSTEM},
                    {"role": "user",   "content": prompt},
                ],
                temperature=0.2,
                max_tokens=1000,
                label="replan",
            )
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            adj = json.loads(raw)
            self._log_commander(f"Tactical update: {adj.get('commentary', '')}")

        except Exception as e:
            self._log(f"[Commander] Re-plan failed: {e}", "warning")

    # ── Final report ──────────────────────────────────────────────────────────

    async def _generate_final_report(self):
        # Cap findings to keep prompt under Grok's context limit
        findings_capped = self._all_findings[:20]
        for f in findings_capped:
            if len(f.get("detail", "")) > 150:
                f = dict(f)  # don't mutate the original
                f["detail"] = f["detail"][:150] + "…"
        finding_summary = json.dumps(findings_capped, indent=2)
        ctx = self._campaign_context
        prompt = f"""
Campaign complete. Generate a concise executive summary for:

Target: {self._target}
Objective: {self._objective}
Total findings: {len(self._all_findings)}
Hosts discovered: {len(ctx.get("hosts_discovered", []))}
Confirmed vulnerabilities: {len(ctx.get("vulnerabilities_confirmed", []))}
Credentials captured: {len(ctx.get("credentials_found", []))}
Shells obtained: {len(ctx.get("shells_obtained", []))}
Pivot paths: {len(ctx.get("pivot_paths", []))}

Tech stack: {str(ctx.get("tech_stack","{}"))[:300]}
Agent summaries: {ctx.get("agent_summaries",[])}

Key findings (first 50):
{finding_summary}

Return JSON:
{{
  "executive_summary": "...",
  "risk_rating": "critical|high|medium|low",
  "top_findings": ["...", "..."],
  "recommended_actions": ["...", "..."],
  "opsec_budget_remaining": {self._opsec_budget}
}}
"""
        try:
            raw = await self._grok_call(
                messages=[
                    {"role": "system", "content": ORCHESTRATOR_SYSTEM},
                    {"role": "user",   "content": prompt},
                ],
                temperature=0.2,
                max_tokens=1500,
                label="final report",
            )
            if raw.startswith("```"):
                raw = raw.split("```")[1]
                if raw.startswith("json"):
                    raw = raw[4:]
            report = json.loads(raw)
            self._log_commander(
                f"FINAL REPORT\n"
                f"Risk Rating: {report.get('risk_rating','').upper()}\n\n"
                f"{report.get('executive_summary','')}\n\n"
                f"Top Findings:\n" + "\n".join(f"  • {f}" for f in report.get("top_findings", [])) + "\n\n"
                f"Recommended Actions:\n" + "\n".join(f"  → {a}" for a in report.get("recommended_actions", []))
            )
        except Exception as e:
            self._log(f"[Commander] Final report generation failed: {e}", "error")

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _merge_campaign_context(self, result: dict):
        """
        Merge an agent result dict into the shared campaign context.
        List fields are appended (deduped), dict fields are merged.
        This is the core of cross-lane intelligence sharing.
        """
        LIST_KEYS = [
            "findings", "hosts_discovered", "web_targets", "subdomains",
            "potential_cves", "exploit_targets", "vulnerabilities_confirmed",
            "credentials_found", "pivot_candidates", "shells_obtained",
            "validated_findings", "exposed_paths", "exploit_db_matches",
            "pivot_paths", "hashes_captured", "sensitive_data",
        ]
        DICT_KEYS = ["tech_stack", "domain_info", "dns_records"]

        for key in LIST_KEYS:
            if key in result and result[key]:
                existing = self._campaign_context.setdefault(key, [])
                for item in result[key]:
                    # Items can be dicts OR plain strings (e.g. subdomains, web_targets)
                    if isinstance(item, dict):
                        dup_key = (item.get("title") or item.get("signal")
                                   or item.get("id") or item.get("url")
                                   or item.get("ip") or str(item))
                        if not any(
                            (e.get("title") if isinstance(e, dict) else e) == dup_key
                            or (e.get("signal") if isinstance(e, dict) else e) == dup_key
                            or (e.get("ip") if isinstance(e, dict) else e) == dup_key
                            or str(e) == str(item)
                            for e in existing
                        ):
                            existing.append(item)
                    else:
                        # Plain string — just deduplicate by value
                        if item not in existing:
                            existing.append(item)

        for key in DICT_KEYS:
            if key in result and result[key]:
                if isinstance(result[key], dict):
                    self._campaign_context.setdefault(key, {}).update(result[key])

        # Forward recommended_next as context for next agents
        if "recommended_next" in result:
            self._campaign_context["recommended_next"] = result["recommended_next"]

        # Keep summary text from each agent
        if "summary" in result:
            summaries = self._campaign_context.setdefault("agent_summaries", [])
            summaries.append(result["summary"])

    def _handle_finding(self, finding: dict):
        finding["timestamp"] = finding.get("timestamp") or datetime.now().isoformat()
        self._all_findings.append(finding)
        self.on_finding(finding)
        if self._memory:
            self._memory.record_finding(finding)

    def _log(self, message: str, level: str = "info"):
        self.on_log(message, level)

    def _log_commander(self, text: str):
        self.on_commander(text)
        self._log(f"[Commander] {text[:120]}", "info")
