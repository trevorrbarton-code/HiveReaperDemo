# HiveReaper v2 — Grok Swarm Edition

Autonomous red-team platform powered by **xAI Grok** as the Hive Orchestrator,
coordinating a swarm of specialised pentest agents.

---

## Architecture

```
HiveReaperMainWindow (PyQt6 UI)
        │
        │  launches
        ▼
CampaignRunner (QThread)
        │
        │  runs async event loop
        ▼
HiveOrchestrator  ←─── Grok (grok-3 via xAI API)
        │
        │  spawns parallel lanes
        ├──────────────────────────────────────┐
        ▼                                      ▼
  Lane lane-1                           Lane lane-2
  ReconAgent → FingerprintAgent     ReconAgent → ExploitAgent
  → ExploitAgent → ValidateAgent    → ValidateAgent
        │                                      │
        └──────────────┬───────────────────────┘
                       ▼
                 Lane lane-N (final)
                 PivotAgent → ReportAgent
```

### Agents

| Agent | Role |
|---|---|
| **ReconAgent** | DNS, OSINT, port scan planning |
| **FingerprintAgent** | Service versions, CVE surface, tech stack |
| **ExploitAgent** | Vulnerability exploitation, credential capture |
| **ValidateAgent** | Deduplication, false-positive removal, CVSS scoring |
| **PivotAgent** | Lateral movement, credential reuse, AD enumeration |
| **ReportAgent** | Structured JSON pentest report to `reports/` |

---

## Setup

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Run the UI
python main_window.py
```

## Usage

1. **Enter your xAI Grok API key** in the left panel (get one at https://console.x.ai)
2. **Set the target** — IP, CIDR range, or domain
3. **Select objective** — full pentest, web audit, AD assessment, etc.
4. **Choose OpSec mode**:
   - `ghost` — passive only, no active probing
   - `stealth` — low-and-slow (recommended)
   - `normal` — standard pentest cadence
   - `loud` — speed over stealth
5. **Set max lanes** — parallel attack lanes (1–5)
6. **Launch** — Grok generates the attack plan and coordinates agents

## Output

- **Lanes tab** — live lane status with per-agent progress and OpSec budget
- **Commander tab** — Grok's real-time tactical narration
- **Findings tab** — all discovered vulnerabilities, click for detail
- **Log tab** — full structured log with severity highlighting
- `reports/report_<timestamp>_<target>.json` — final pentest report

---

## Notes

- All agents use **Grok (grok-3)** for reasoning — no actual tools are executed.
  To wire in real tool execution (nmap, ffuf, sqlmap etc.), implement tool-calling
  inside each agent's `_build_task()` and parse real output alongside the Grok response.
- The `CampaignRunner` runs a full `asyncio` event loop in a `QThread`, keeping
  the UI fully responsive during multi-lane campaigns.
- OpSec budget is tracked centrally by the orchestrator and propagated to all lane cards.
