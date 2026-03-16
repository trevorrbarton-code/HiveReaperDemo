"""
HiveReaper v2 — Experience Store
SQLite-backed long-term memory for the swarm.

Three tables:
  episodes  — full campaign records (what happened, what worked)
  patterns  — extracted attack patterns (signal → finding rules)
  strategies — winning agent sequences per target type

Retrieval uses keyword + tag similarity — no vector DB needed.
Grok does the semantic matching when we inject memory into prompts.
"""

import json
import sqlite3
import hashlib
from datetime import datetime
from pathlib import Path
from typing import Optional

DB_PATH = Path("memory/hivereaper_memory.db")


def _conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(exist_ok=True)
    con = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    return con


def init_db():
    con = _conn()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS episodes (
        id            TEXT PRIMARY KEY,
        timestamp     TEXT NOT NULL,
        target        TEXT NOT NULL,
        target_type   TEXT,          -- web / ad / ctf / network / api
        objective     TEXT,
        opsec_mode    TEXT,
        outcome       TEXT,          -- success / partial / failed
        duration_secs INTEGER,
        flags_found   TEXT,          -- JSON list of flags (CTF mode)
        findings_json TEXT,          -- JSON list of all findings
        attack_path   TEXT,          -- JSON ordered list of steps that led to success
        tools_used    TEXT,          -- JSON list of tools that produced results
        lessons       TEXT,          -- Grok-generated lessons learned
        tags          TEXT,          -- JSON list of tags: ["apache","sqli","ctf","thm"]
        source        TEXT           -- "thm" / "htb" / "live" / "manual"
    );

    CREATE TABLE IF NOT EXISTS patterns (
        id            TEXT PRIMARY KEY,
        created       TEXT NOT NULL,
        signal        TEXT NOT NULL,  -- what to look for (e.g. "Apache 2.4.49")
        signal_type   TEXT,           -- version / port / service / header / response
        action        TEXT NOT NULL,  -- what to do when signal is seen
        finding_type  TEXT,           -- what kind of finding this leads to
        cve_id        TEXT,
        success_count INTEGER DEFAULT 1,
        fail_count    INTEGER DEFAULT 0,
        tags          TEXT,
        example_evidence TEXT         -- real output snippet that triggered this
    );

    CREATE TABLE IF NOT EXISTS strategies (
        id            TEXT PRIMARY KEY,
        created       TEXT NOT NULL,
        target_type   TEXT NOT NULL,  -- web / ad / ctf_linux / ctf_windows / etc
        agent_sequence TEXT NOT NULL, -- JSON ordered agent list
        avg_duration  INTEGER,        -- average seconds to complete
        success_rate  REAL,           -- 0.0-1.0
        notes         TEXT,
        times_used    INTEGER DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS hints (
        id            TEXT PRIMARY KEY,
        created       TEXT NOT NULL,
        episode_id    TEXT,
        hint_text     TEXT NOT NULL,
        context       TEXT,           -- what state the agent was in when hint given
        outcome       TEXT            -- what happened after the hint
    );

    CREATE INDEX IF NOT EXISTS idx_episodes_target_type ON episodes(target_type);
    CREATE INDEX IF NOT EXISTS idx_episodes_outcome      ON episodes(outcome);
    CREATE INDEX IF NOT EXISTS idx_patterns_signal       ON patterns(signal);
    CREATE INDEX IF NOT EXISTS idx_strategies_type       ON strategies(target_type);
    """)
    con.commit()
    con.close()


class ExperienceStore:
    """Main interface for the memory system."""

    def __init__(self):
        init_db()
        self._con = _conn()

    # ── Episode management ────────────────────────────────────────────────────

    def save_episode(self, episode: dict) -> str:
        """Store a completed campaign episode. Returns the episode ID."""
        eid = hashlib.sha256(
            f"{episode.get('target')}{episode.get('timestamp',datetime.now().isoformat())}".encode()
        ).hexdigest()[:16]

        self._con.execute("""
            INSERT OR REPLACE INTO episodes
            (id, timestamp, target, target_type, objective, opsec_mode,
             outcome, duration_secs, flags_found, findings_json,
             attack_path, tools_used, lessons, tags, source)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            eid,
            episode.get("timestamp", datetime.now().isoformat()),
            episode.get("target", ""),
            episode.get("target_type", "unknown"),
            episode.get("objective", ""),
            episode.get("opsec_mode", "normal"),
            episode.get("outcome", "unknown"),
            episode.get("duration_secs", 0),
            json.dumps(episode.get("flags_found", [])),
            json.dumps(episode.get("findings", [])),
            json.dumps(episode.get("attack_path", [])),
            json.dumps(episode.get("tools_used", [])),
            episode.get("lessons", ""),
            json.dumps(episode.get("tags", [])),
            episode.get("source", "live"),
        ))
        self._con.commit()
        return eid

    def get_similar_episodes(
        self, target: str, target_type: str = None,
        tags: list[str] = None, limit: int = 5
    ) -> list[dict]:
        """
        Retrieve the most relevant past episodes for context injection.
        Simple keyword matching — Grok handles semantic relevance.
        """
        rows = []

        # Direct target match first
        cur = self._con.execute(
            "SELECT * FROM episodes WHERE target LIKE ? ORDER BY timestamp DESC LIMIT ?",
            (f"%{target.split('/')[0].split('.')[0]}%", limit)
        )
        rows.extend(cur.fetchall())

        # Target type match
        if target_type and len(rows) < limit:
            cur = self._con.execute(
                "SELECT * FROM episodes WHERE target_type=? ORDER BY timestamp DESC LIMIT ?",
                (target_type, limit - len(rows))
            )
            rows.extend(cur.fetchall())

        # Tag overlap
        if tags and len(rows) < limit:
            for tag in tags[:3]:
                cur = self._con.execute(
                    "SELECT * FROM episodes WHERE tags LIKE ? ORDER BY timestamp DESC LIMIT ?",
                    (f'%"{tag}"%', limit - len(rows))
                )
                rows.extend(cur.fetchall())

        # Recent successful ones as fallback
        if len(rows) < limit:
            cur = self._con.execute(
                "SELECT * FROM episodes WHERE outcome='success' ORDER BY timestamp DESC LIMIT ?",
                (limit - len(rows),)
            )
            rows.extend(cur.fetchall())

        # Dedupe by id
        seen = set()
        unique = []
        for r in rows:
            if r["id"] not in seen:
                seen.add(r["id"])
                unique.append(dict(r))
        return unique[:limit]

    def get_all_episodes(self, limit: int = 200) -> list[dict]:
        cur = self._con.execute(
            "SELECT * FROM episodes ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        return [dict(r) for r in cur.fetchall()]

    def get_episode_count(self) -> dict:
        row = self._con.execute("""
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN outcome='success' THEN 1 ELSE 0 END) as successes,
                SUM(CASE WHEN source='thm' THEN 1 ELSE 0 END) as thm,
                SUM(CASE WHEN source='live' THEN 1 ELSE 0 END) as live
            FROM episodes
        """).fetchone()
        return dict(row) if row else {}

    # ── Pattern management ────────────────────────────────────────────────────

    def save_pattern(self, pattern: dict) -> str:
        pid = hashlib.sha256(
            f"{pattern.get('signal')}{pattern.get('action')}".encode()
        ).hexdigest()[:16]

        existing = self._con.execute(
            "SELECT id, success_count FROM patterns WHERE id=?", (pid,)
        ).fetchone()

        if existing:
            self._con.execute(
                "UPDATE patterns SET success_count=success_count+1 WHERE id=?", (pid,)
            )
        else:
            self._con.execute("""
                INSERT INTO patterns
                (id, created, signal, signal_type, action, finding_type,
                 cve_id, tags, example_evidence)
                VALUES (?,?,?,?,?,?,?,?,?)
            """, (
                pid,
                datetime.now().isoformat(),
                pattern.get("signal", ""),
                pattern.get("signal_type", ""),
                pattern.get("action", ""),
                pattern.get("finding_type", ""),
                pattern.get("cve_id", ""),
                json.dumps(pattern.get("tags", [])),
                pattern.get("example_evidence", ""),
            ))
        self._con.commit()
        return pid

    def get_patterns_for_context(self, tool_output: str, limit: int = 20) -> list[dict]:
        """
        Match patterns against real tool output.
        Returns patterns whose signal appears in the output.
        """
        all_patterns = self._con.execute(
            "SELECT * FROM patterns ORDER BY success_count DESC LIMIT 200"
        ).fetchall()

        matched = []
        output_lower = tool_output.lower()
        for p in all_patterns:
            signal = p["signal"].lower()
            if signal and signal in output_lower:
                matched.append(dict(p))
            if len(matched) >= limit:
                break
        return matched

    def get_all_patterns(self) -> list[dict]:
        return [dict(r) for r in
                self._con.execute("SELECT * FROM patterns ORDER BY success_count DESC").fetchall()]

    # ── Strategy management ───────────────────────────────────────────────────

    def save_strategy(self, strategy: dict):
        sid = hashlib.sha256(
            f"{strategy.get('target_type')}{json.dumps(strategy.get('agent_sequence',[]))}".encode()
        ).hexdigest()[:16]

        existing = self._con.execute(
            "SELECT id, times_used, avg_duration, success_rate FROM strategies WHERE id=?",
            (sid,)
        ).fetchone()

        if existing:
            new_times   = existing["times_used"] + 1
            new_avg_dur = int((existing["avg_duration"] + strategy.get("duration_secs", 0)) / 2)
            new_success = ((existing["success_rate"] * existing["times_used"]) +
                           (1.0 if strategy.get("success") else 0.0)) / new_times
            self._con.execute(
                """UPDATE strategies
                   SET times_used=?, avg_duration=?, success_rate=?, notes=?
                   WHERE id=?""",
                (new_times, new_avg_dur, new_success,
                 strategy.get("notes", ""), sid)
            )
        else:
            self._con.execute("""
                INSERT INTO strategies
                (id, created, target_type, agent_sequence, avg_duration,
                 success_rate, notes)
                VALUES (?,?,?,?,?,?,?)
            """, (
                sid,
                datetime.now().isoformat(),
                strategy.get("target_type", "unknown"),
                json.dumps(strategy.get("agent_sequence", [])),
                strategy.get("duration_secs", 0),
                1.0 if strategy.get("success") else 0.0,
                strategy.get("notes", ""),
            ))
        self._con.commit()

    def get_best_strategy(self, target_type: str) -> Optional[dict]:
        row = self._con.execute(
            """SELECT * FROM strategies
               WHERE target_type=?
               ORDER BY success_rate DESC, times_used DESC
               LIMIT 1""",
            (target_type,)
        ).fetchone()
        return dict(row) if row else None

    # ── Hint storage ──────────────────────────────────────────────────────────

    def save_hint(self, episode_id: str, hint_text: str,
                  context: str = "", outcome: str = "") -> str:
        hid = hashlib.sha256(
            f"{episode_id}{hint_text}".encode()
        ).hexdigest()[:16]
        self._con.execute("""
            INSERT OR REPLACE INTO hints
            (id, created, episode_id, hint_text, context, outcome)
            VALUES (?,?,?,?,?,?)
        """, (hid, datetime.now().isoformat(), episode_id,
              hint_text, context, outcome))
        self._con.commit()
        return hid

    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        ep  = self.get_episode_count()
        pat = self._con.execute("SELECT COUNT(*) as c FROM patterns").fetchone()["c"]
        strat = self._con.execute("SELECT COUNT(*) as c FROM strategies").fetchone()["c"]
        hints = self._con.execute("SELECT COUNT(*) as c FROM hints").fetchone()["c"]
        return {
            "episodes":   ep.get("total", 0),
            "successes":  ep.get("successes", 0),
            "thm_boxes":  ep.get("thm", 0),
            "live_engagements": ep.get("live", 0),
            "patterns":   pat,
            "strategies": strat,
            "hints":      hints,
        }

    def close(self):
        self._con.close()
