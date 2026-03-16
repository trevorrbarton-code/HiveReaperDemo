"""
HiveReaper v2 — Campaign Runner
Bridges the async Grok swarm to the Qt main window via signals.
Runs the full asyncio event loop in a QThread.
"""

import asyncio
import uuid
from PyQt6.QtCore import QThread, pyqtSignal

from orchestrator.hive_orchestrator import HiveOrchestrator


class CampaignRunner(QThread):
    """
    QThread wrapper for the async orchestrator.
    All signals are emitted on the Qt main thread automatically.
    """

    log_signal         = pyqtSignal(str, str)          # message, level
    lane_update_signal = pyqtSignal(str, str, str, int, int)  # lane_id, state, agent, progress, budget
    finding_signal     = pyqtSignal(dict)
    commander_signal   = pyqtSignal(str)
    complete_signal    = pyqtSignal()

    def __init__(
        self,
        api_key:    str,
        target:     str,
        objective:  str,
        opsec_mode: str  = "stealth",
        max_lanes:  int  = 5,
        parent=None,
    ):
        super().__init__(parent)
        self.api_key    = api_key
        self.target     = target
        self.objective  = objective
        self.opsec_mode = opsec_mode
        self.max_lanes  = max_lanes

        self._orchestrator: HiveOrchestrator | None = None

    def run(self):
        """Runs in the QThread — creates its own asyncio event loop."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        self._orchestrator = HiveOrchestrator(
            api_key        = self.api_key,
            on_log         = lambda msg, lvl: self.log_signal.emit(msg, lvl),
            on_lane_update = lambda lid, state, agent, prog, budget:
                             self.lane_update_signal.emit(lid, state, agent, prog, budget),
            on_finding     = lambda f: self.finding_signal.emit(f),
            on_commander   = lambda t: self.commander_signal.emit(t),
            on_complete    = lambda: self.complete_signal.emit(),
        )

        campaign_id = str(uuid.uuid4())[:8]

        try:
            loop.run_until_complete(
                self._orchestrator.run_campaign(
                    campaign_id = campaign_id,
                    target      = self.target,
                    objective   = self.objective,
                    opsec_mode  = self.opsec_mode,
                    max_lanes   = self.max_lanes,
                )
            )
        finally:
            loop.close()

    def abort(self):
        if self._orchestrator:
            self._orchestrator.abort()
