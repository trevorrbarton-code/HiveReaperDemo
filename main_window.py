"""
HiveReaper v2 — Main Application Window (Enterprise UI)
Grok-powered swarm edition.

Changes from v1:
  - API key input in the left panel
  - Campaign launch wires to CampaignRunner (QThread → async Grok swarm)
  - Commander panel shows Grok's real-time tactical commentary
  - Abort properly cancels the async swarm
"""

import sys
import os
import asyncio
from datetime import datetime
from typing import Dict

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QTextEdit, QPushButton, QComboBox,
    QTableWidget, QTableWidgetItem, QHeaderView, QSplitter,
    QProgressBar, QTabWidget, QFrame, QScrollArea,
    QStatusBar, QMessageBox
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import (
    QColor, QPalette, QFont, QTextCursor,
    QSyntaxHighlighter, QTextCharFormat, QIcon, QPixmap
)

from campaign_runner import CampaignRunner
from ui.memory_tab import MemoryTab

# ─── Design Tokens ────────────────────────────────────────────────────────────
C = {
    "bg":       "#090d13",
    "bg2":      "#0d1119",
    "bg3":      "#111621",
    "bg4":      "#161b27",
    "border":   "#1e2535",
    "border2":  "#28304a",
    "border3":  "#333d58",
    "text":     "#dde3f0",
    "text2":    "#7a869e",
    "text3":    "#3d4a62",
    "accent":   "#3b82f6",
    "accent_d": "#1d4ed8",
    "cyan":     "#06b6d4",
    "green":    "#10b981",
    "amber":    "#f59e0b",
    "red":      "#ef4444",
    "purple":   "#8b5cf6",
    "wait":     "#f59e0b",
    "active":   "#06b6d4",
    "complete": "#10b981",
    "error":    "#ef4444",
    "idle":     "#3d4a62",
}
MONO = "JetBrains Mono, Cascadia Code, Fira Code, Consolas, monospace"
SANS = "Inter, Segoe UI, Helvetica Neue, sans-serif"

CAMPAIGN_OBJECTIVES = [
    "Full penetration test",
    "External network assessment",
    "Web application audit",
    "Active Directory / internal assessment",
    "Ransomware readiness assessment",
    "CTF / lab target",
    "Custom objective…",
]
OPSEC_MODES = ["ghost", "stealth", "normal", "loud"]


def px(widget, qss: str):
    widget.setStyleSheet(qss)


# ─── Log Highlighter ─────────────────────────────────────────────────────────
class LogHighlighter(QSyntaxHighlighter):
    RULES = [
        (["ERROR", "FATAL", "CRITICAL", "EXCEPTION"],    "#ef4444"),
        (["WARNING", "WARN", "VETOED"],                  "#f59e0b"),
        (["SUCCESS", "CONFIRMED", "GAINED", "COMPLETE"], "#10b981"),
        (["INFO", "STARTING", "LAUNCH"],                 "#06b6d4"),
        (["DEBUG", "TRACE"],                             "#3d4a62"),
    ]

    def highlightBlock(self, text):
        upper = text.upper()
        for keywords, color in self.RULES:
            if any(k in upper for k in keywords):
                fmt = QTextCharFormat()
                fmt.setForeground(QColor(color))
                self.setFormat(0, len(text), fmt)
                return


# ─── Stat Card ───────────────────────────────────────────────────────────────
class StatCard(QWidget):
    def __init__(self, label: str, value: str, accent_color: str, parent=None):
        super().__init__(parent)
        self._accent = accent_color
        self.setObjectName("statcard")
        self.setStyleSheet("QWidget#statcard { background: transparent; }")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 10, 16, 8)
        lay.setSpacing(3)
        lbl = QLabel(label.upper())
        lbl.setFont(QFont(SANS, 8, QFont.Weight.Bold))
        lbl.setStyleSheet(f"color: {C['text3']}; letter-spacing: 2px; background: transparent;")
        lay.addWidget(lbl)
        self._val = QLabel(value)
        self._val.setFont(QFont(MONO, 20))
        self._val.setStyleSheet(f"color: {C['text']}; background: transparent;")
        lay.addWidget(self._val)
        self._sub = QLabel("")
        self._sub.setFont(QFont(SANS, 8))
        self._sub.setStyleSheet(f"color: {C['text3']}; background: transparent;")
        lay.addWidget(self._sub)
        bar = QFrame(self)
        bar.setStyleSheet(f"background-color: {accent_color}; border: none;")
        bar.setFixedHeight(2)
        self._bar = bar

    def resizeEvent(self, e):
        self._bar.setGeometry(0, self.height() - 2, self.width(), 2)
        super().resizeEvent(e)

    def set_value(self, v: str):
        self._val.setText(v)

    def set_sub(self, v: str):
        self._sub.setText(v)


# ─── Metrics Bar ─────────────────────────────────────────────────────────────
class MetricsBar(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(78)
        self.setObjectName("metricsbar")
        self.setStyleSheet(f"QWidget#metricsbar {{ background-color: {C['bg2']}; border-bottom: 1px solid {C['border']}; }}")
        lay = QHBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)
        specs = [
            ("Active Lanes",  "0",     C["cyan"],  "of 5 capacity"),
            ("Findings",      "0",     C["text2"], "0 critical"),
            ("Exploitable",   "0",     C["red"],   "attack surface"),
            ("OpSec Budget",  "100%",  C["green"], "no violations"),
            ("Campaign Time", "00:00", C["amber"], "elapsed"),
        ]
        self._cards: Dict[str, StatCard] = {}
        for i, (label, val, color, sub) in enumerate(specs):
            card = StatCard(label, val, color)
            card.set_sub(sub)
            if i > 0:
                div = QFrame()
                div.setFrameShape(QFrame.Shape.VLine)
                div.setStyleSheet(f"color: {C['border']}; border: none; background: {C['border']};")
                div.setFixedWidth(1)
                lay.addWidget(div)
            lay.addWidget(card, stretch=1)
            self._cards[label] = card

    def update(self, name: str, value: str):
        if name in self._cards:
            self._cards[name].set_value(value)


# ─── Lane Card ───────────────────────────────────────────────────────────────
class LaneCard(QWidget):
    STATE_COLORS = {
        "WAITING":   C["wait"],
        "PLANNING":  C["accent"],
        "ANALYZING": C["accent"],
        "EXECUTING": C["active"],
        "COMPLETE":  C["complete"],
        "ERROR":     C["error"],
        "IDLE":      C["idle"],
        "WAITING_FOR_TOOL": C["wait"],
    }

    def __init__(self, lane_id: str, target: str, parent=None):
        super().__init__(parent)
        self.setObjectName("lanecard")
        self.setStyleSheet(f"QWidget#lanecard {{ background-color: {C['bg3']}; border: 1px solid {C['border2']}; border-radius: 8px; }}")

        root = QVBoxLayout(self)
        root.setContentsMargins(14, 12, 14, 12)
        root.setSpacing(8)

        hdr = QHBoxLayout()
        hdr.setSpacing(8)
        self._dot = QLabel("●")
        self._dot.setFixedWidth(12)
        self._dot.setStyleSheet(f"color: {C['idle']}; font-size: 9px; background: transparent;")
        hdr.addWidget(self._dot)

        lid = QLabel(lane_id[:14])
        lid.setFont(QFont(MONO, 10, QFont.Weight.Medium))
        lid.setStyleSheet(f"color: {C['accent']}; background: transparent;")
        hdr.addWidget(lid)

        tgt = QLabel(target)
        tgt.setFont(QFont(MONO, 9))
        tgt.setStyleSheet(f"color: {C['text3']}; background: transparent;")
        hdr.addWidget(tgt)
        hdr.addStretch()

        self._state_lbl = QLabel("IDLE")
        self._state_lbl.setFont(QFont(SANS, 8, QFont.Weight.Bold))
        self._state_lbl.setStyleSheet(f"color: {C['idle']}; letter-spacing: 1px; background: transparent;")
        hdr.addWidget(self._state_lbl)
        root.addLayout(hdr)

        self._agent_lbl = QLabel("Agent: —")
        self._agent_lbl.setFont(QFont(SANS, 9))
        self._agent_lbl.setStyleSheet(f"color: {C['text3']}; background: transparent;")
        root.addWidget(self._agent_lbl)

        pr = QHBoxLayout()
        pl = QLabel("Progress")
        pl.setFont(QFont(SANS, 8))
        pl.setStyleSheet(f"color: {C['text3']}; background: transparent;")
        pr.addWidget(pl)
        pr.addStretch()
        self._prog_pct = QLabel("0%")
        self._prog_pct.setFont(QFont(MONO, 8))
        self._prog_pct.setStyleSheet(f"color: {C['text2']}; background: transparent;")
        pr.addWidget(self._prog_pct)
        root.addLayout(pr)

        self._prog_bar = self._make_bar(C["accent"])
        root.addWidget(self._prog_bar)

        opr = QHBoxLayout()
        opl = QLabel("OpSec Budget")
        opl.setFont(QFont(SANS, 8))
        opl.setStyleSheet(f"color: {C['text3']}; background: transparent;")
        opr.addWidget(opl)
        opr.addStretch()
        self._ops_pct = QLabel("100%")
        self._ops_pct.setFont(QFont(MONO, 8))
        self._ops_pct.setStyleSheet(f"color: {C['green']}; background: transparent;")
        opr.addWidget(self._ops_pct)
        root.addLayout(opr)

        self._ops_bar = self._make_bar(C["green"])
        self._ops_bar.setValue(100)
        root.addWidget(self._ops_bar)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(f"border: none; border-top: 1px solid {C['border']}; background: transparent;")
        sep.setFixedHeight(1)
        root.addWidget(sep)

        self._mini_log = QLabel("—")
        self._mini_log.setFont(QFont(MONO, 8))
        self._mini_log.setStyleSheet(f"color: {C['text3']}; background: transparent;")
        self._mini_log.setWordWrap(True)
        root.addWidget(self._mini_log)

    def _make_bar(self, color: str) -> QProgressBar:
        b = QProgressBar()
        b.setRange(0, 100)
        b.setValue(0)
        b.setTextVisible(False)
        b.setFixedHeight(5)
        b.setStyleSheet(f"""
            QProgressBar {{ background-color: {C['border']}; border: none; border-radius: 2px; }}
            QProgressBar::chunk {{ background-color: {color}; border-radius: 2px; }}
        """)
        return b

    def update_state(self, state: str, agent: str = "", progress: int = None, budget: int = None):
        color = self.STATE_COLORS.get(state, C["text2"])
        self._dot.setStyleSheet(f"color: {color}; font-size: 9px; background: transparent;")
        self._state_lbl.setText(state[:10])
        self._state_lbl.setStyleSheet(f"color: {color}; letter-spacing: 1px; background: transparent;")
        if agent:
            self._agent_lbl.setText(f"Agent: {agent}")
        if progress is not None:
            self._prog_bar.setValue(progress)
            self._prog_pct.setText(f"{progress}%")
        if budget is not None:
            self._ops_bar.setValue(budget)
            self._ops_pct.setText(f"{budget}%")
            bc = C["green"] if budget > 60 else (C["amber"] if budget > 30 else C["red"])
            self._ops_bar.setStyleSheet(f"""
                QProgressBar {{ background-color: {C['border']}; border: none; border-radius: 2px; }}
                QProgressBar::chunk {{ background-color: {bc}; border-radius: 2px; }}
            """)
            self._ops_pct.setStyleSheet(f"color: {bc}; background: transparent;")

    def add_log_entry(self, message: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self._mini_log.setText(f"[{ts}] {message}")


# ─── Button helpers ───────────────────────────────────────────────────────────
def make_btn(text: str, variant: str = "ghost") -> QPushButton:
    btn = QPushButton(text)
    btn.setFixedHeight(36)
    btn.setCursor(Qt.CursorShape.PointingHandCursor)
    btn.setFont(QFont(SANS, 10, QFont.Weight.Medium))
    if variant == "primary":
        btn.setStyleSheet(f"""
            QPushButton {{ background-color: {C['accent']}; color: #fff; border: none;
                           border-radius: 6px; padding: 0 18px; }}
            QPushButton:hover {{ background-color: {C['accent_d']}; }}
            QPushButton:disabled {{ background-color: {C['bg4']}; color: {C['text3']}; }}
        """)
    elif variant == "danger":
        btn.setStyleSheet(f"""
            QPushButton {{ background-color: rgba(239,68,68,0.15); color: {C['red']};
                           border: 1px solid rgba(239,68,68,0.35); border-radius: 6px; padding: 0 16px; }}
            QPushButton:hover {{ background-color: rgba(239,68,68,0.25); }}
            QPushButton:disabled {{ color: {C['text3']}; border-color: {C['border']}; background: transparent; }}
        """)
    else:
        btn.setStyleSheet(f"""
            QPushButton {{ background-color: {C['bg4']}; color: {C['text2']};
                           border: 1px solid {C['border2']}; border-radius: 6px; padding: 0 14px; }}
            QPushButton:hover {{ color: {C['text']}; border-color: {C['border3']}; background: {C['bg3']}; }}
        """)
    return btn


def section_lbl(text: str) -> QLabel:
    lbl = QLabel(text.upper())
    lbl.setFont(QFont(SANS, 8, QFont.Weight.Bold))
    lbl.setStyleSheet(f"color: {C['text3']}; letter-spacing: 2px; padding: 10px 0 5px 0; background: transparent;")
    return lbl


# ─── Main Window ─────────────────────────────────────────────────────────────
class HiveReaperMainWindow(QMainWindow):
    log_signal         = pyqtSignal(str, str)
    lane_update_signal = pyqtSignal(str, str, str, int, int)
    finding_signal     = pyqtSignal(dict)
    stats_signal       = pyqtSignal(dict)
    commander_signal   = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("HiveReaper v2")
        self.setMinimumSize(1400, 900)
        self._apply_palette()
        self._apply_global_style()
        self._setup_ui()
        self._apply_icon()

        self.log_signal.connect(self._append_log)
        self.lane_update_signal.connect(self._update_lane_card)
        self.finding_signal.connect(self._add_finding)
        self.stats_signal.connect(self._update_stats)
        self.commander_signal.connect(self._append_commander)

        self.lane_cards: Dict[str, LaneCard] = {}
        self.campaign_start_time = None
        self._last_log_message   = ""
        self._last_log_count     = 0
        self._finding_details    = {}
        self._shown_finding_ids  = set()
        self._runner: CampaignRunner | None = None
        self._placeholder_visible = True

        self._clock_timer = QTimer()
        self._clock_timer.timeout.connect(self._tick_clock)
        self._elapsed = 0

    # ── Palette / Styles ─────────────────────────────────────────────────────
    def _apply_icon(self):
        """Set window icon from bundled PNG, with SVG fallback."""
        import os
        # Look for icon relative to this file
        base = os.path.dirname(os.path.abspath(__file__))
        icon_path = os.path.join(base, "HiveReaper_Icon.png")
        if os.path.exists(icon_path):
            icon = QIcon(icon_path)
            self.setWindowIcon(icon)
            # Also set the app-level icon so it shows in the taskbar
            from PyQt6.QtWidgets import QApplication
            QApplication.instance().setWindowIcon(icon)
        else:
            # Fallback: render the ⬡ hex as a pixmap
            pix = QPixmap(64, 64)
            pix.fill(QColor("#c97800"))
            self.setWindowIcon(QIcon(pix))

    def _apply_palette(self):
        p = QPalette()
        p.setColor(QPalette.ColorRole.Window,        QColor(C["bg"]))
        p.setColor(QPalette.ColorRole.WindowText,    QColor(C["text"]))
        p.setColor(QPalette.ColorRole.Base,          QColor(C["bg2"]))
        p.setColor(QPalette.ColorRole.AlternateBase, QColor(C["bg3"]))
        p.setColor(QPalette.ColorRole.Text,          QColor(C["text"]))
        p.setColor(QPalette.ColorRole.Button,        QColor(C["bg3"]))
        p.setColor(QPalette.ColorRole.ButtonText,    QColor(C["text"]))
        p.setColor(QPalette.ColorRole.Highlight,     QColor(C["accent"]))
        p.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
        self.setPalette(p)

    def _apply_global_style(self):
        self.setStyleSheet(f"""
            QMainWindow {{ background-color: {C['bg']}; }}
            QWidget {{ color: {C['text']}; font-family: {SANS}; font-size: 12px; }}
            QScrollBar:vertical {{ background: {C['bg2']}; width: 6px; border-radius: 3px; margin: 0; }}
            QScrollBar::handle:vertical {{ background: {C['border3']}; border-radius: 3px; min-height: 24px; }}
            QScrollBar::handle:vertical:hover {{ background: {C['accent']}; }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; border: none; }}
            QLineEdit {{ background-color: {C['bg3']}; color: {C['text']}; border: 1px solid {C['border2']};
                         border-radius: 5px; padding: 6px 10px; font-size: 12px; }}
            QLineEdit:focus {{ border-color: {C['accent']}; }}
            QComboBox {{ background-color: {C['bg3']}; color: {C['text']}; border: 1px solid {C['border2']};
                         border-radius: 5px; padding: 6px 10px; font-size: 12px; }}
            QComboBox:focus {{ border-color: {C['accent']}; }}
            QComboBox::drop-down {{ border: none; width: 24px; }}
            QComboBox::down-arrow {{ image: none; border-left: 4px solid transparent;
                border-right: 4px solid transparent; border-top: 5px solid {C['text2']}; width: 0; height: 0; }}
            QComboBox QAbstractItemView {{ background-color: {C['bg4']}; color: {C['text']};
                border: 1px solid {C['border2']}; selection-background-color: {C['accent']}; padding: 4px; }}
            QTabWidget::pane {{ border: none; border-top: 1px solid {C['border']}; background-color: {C['bg2']}; }}
            QTabBar::tab {{ background-color: transparent; color: {C['text3']}; padding: 10px 18px;
                margin-right: 2px; border: none; border-bottom: 2px solid transparent;
                font-size: 11px; font-weight: 500; }}
            QTabBar::tab:selected {{ color: {C['text']}; border-bottom: 2px solid {C['accent']}; }}
            QTabBar::tab:hover:!selected {{ color: {C['text2']}; background: rgba(255,255,255,0.02); }}
            QTabBar {{ background-color: {C['bg2']}; border-bottom: 1px solid {C['border']}; }}
            QTableWidget {{ background-color: {C['bg2']}; color: {C['text']}; border: none;
                gridline-color: {C['border']}; font-size: 11px; font-family: {MONO};
                alternate-background-color: {C['bg3']}; }}
            QHeaderView::section {{ background-color: {C['bg3']}; color: {C['text2']}; padding: 8px 10px;
                border: none; border-bottom: 1px solid {C['border2']}; font-size: 10px;
                font-weight: 600; letter-spacing: 1px; font-family: {SANS}; }}
            QTableWidget::item {{ padding: 6px 10px; border-bottom: 1px solid {C['border']}; }}
            QTableWidget::item:selected {{ background: rgba(59,130,246,0.2); color: {C['text']}; }}
            QTextEdit {{ background-color: {C['bg']}; color: {C['text2']}; border: none;
                font-family: {MONO}; font-size: 11px; padding: 10px; }}
            QStatusBar {{ background-color: {C['bg2']}; color: {C['text2']};
                border-top: 1px solid {C['border']}; font-size: 11px; }}
            QStatusBar::item {{ border: none; }}
            QSplitter::handle {{ background-color: {C['border']}; width: 1px; height: 1px; }}
            QScrollArea {{ border: none; background: transparent; }}
        """)

    # ── UI Setup ─────────────────────────────────────────────────────────────
    def _setup_ui(self):
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_topbar())
        self._metrics = MetricsBar()
        root.addWidget(self._metrics)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setChildrenCollapsible(False)
        splitter.addWidget(self._build_left_panel())
        splitter.addWidget(self._build_main_panel())
        splitter.setSizes([320, 1100])
        root.addWidget(splitter, stretch=1)

        self._status = QStatusBar()
        self.setStatusBar(self._status)
        self._status.showMessage("Ready — configure target and API key, then launch.")

    def _build_topbar(self) -> QWidget:
        bar = QWidget()
        bar.setFixedHeight(52)
        bar.setStyleSheet(f"background-color: {C['bg2']}; border-bottom: 1px solid {C['border']};")
        lay = QHBoxLayout(bar)
        lay.setContentsMargins(20, 0, 20, 0)
        lay.setSpacing(12)

        icon = QLabel("⬡")
        icon.setFont(QFont(SANS, 18))
        icon.setStyleSheet(f"color: {C['accent']}; background: transparent;")
        lay.addWidget(icon)

        title = QLabel("HIVE REAPER")
        title.setFont(QFont(SANS, 14, QFont.Weight.Bold))
        title.setStyleSheet(f"color: {C['text']}; letter-spacing: 3px; background: transparent;")
        lay.addWidget(title)

        ver = QLabel("v2  ·  Grok Swarm Edition")
        ver.setFont(QFont(MONO, 9))
        ver.setStyleSheet(f"color: {C['text3']}; background: transparent;")
        lay.addWidget(ver)

        lay.addStretch()

        self._grok_status = QLabel("● Grok: not connected")
        self._grok_status.setFont(QFont(MONO, 9))
        self._grok_status.setStyleSheet(f"color: {C['text3']}; background: transparent;")
        lay.addWidget(self._grok_status)

        self._clock_lbl = QLabel("00:00:00")
        self._clock_lbl.setFont(QFont(MONO, 11))
        self._clock_lbl.setStyleSheet(f"color: {C['text2']}; background: transparent;")
        lay.addWidget(self._clock_lbl)

        return bar

    def _build_left_panel(self) -> QWidget:
        panel = QWidget()
        panel.setMinimumWidth(280)
        panel.setMaximumWidth(360)
        panel.setStyleSheet(f"background-color: {C['bg2']}; border-right: 1px solid {C['border']};")

        lay = QVBoxLayout(panel)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(6)

        # ── API Key ──
        lay.addWidget(section_lbl("Grok API Key"))
        self.api_key_input = QLineEdit()
        self.api_key_input.setPlaceholderText("xai-…")
        self.api_key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.api_key_input.textChanged.connect(self._on_api_key_changed)
        lay.addWidget(self.api_key_input)

        # ── Target ──
        lay.addWidget(section_lbl("Target"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("192.168.1.0/24 or example.com")
        lay.addWidget(self.target_input)

        # ── Objective ──
        lay.addWidget(section_lbl("Campaign Objective"))
        self.objective_combo = QComboBox()
        for obj in CAMPAIGN_OBJECTIVES:
            self.objective_combo.addItem(obj)
        lay.addWidget(self.objective_combo)

        # ── OpSec Mode ──
        lay.addWidget(section_lbl("OpSec Mode"))
        self.opsec_combo = QComboBox()
        for mode in OPSEC_MODES:
            self.opsec_combo.addItem(mode.upper(), mode)
        self.opsec_combo.setCurrentIndex(1)  # stealth
        lay.addWidget(self.opsec_combo)

        # ── Max Lanes ──
        lay.addWidget(section_lbl("Max Parallel Lanes"))
        self.lanes_combo = QComboBox()
        for n in ["1", "2", "3", "4", "5"]:
            self.lanes_combo.addItem(n)
        self.lanes_combo.setCurrentIndex(2)  # 3 lanes default
        lay.addWidget(self.lanes_combo)

        lay.addSpacing(8)

        # ── Launch / Abort ──
        self.launch_btn = make_btn("▶  Launch Campaign", "primary")
        self.launch_btn.clicked.connect(self._launch_campaign)
        lay.addWidget(self.launch_btn)

        self.abort_btn = make_btn("■  Abort Campaign", "danger")
        self.abort_btn.setEnabled(False)
        self.abort_btn.clicked.connect(self._abort_campaign)
        lay.addWidget(self.abort_btn)

        lay.addSpacing(8)

        # ── Agent Roster ──
        lay.addWidget(section_lbl("Agent Roster"))
        agents = [
            ("ReconAgent",       C["cyan"],   "Recon & OSINT"),
            ("FingerprintAgent", C["accent"], "Service ID & CVEs"),
            ("ExploitAgent",     C["red"],    "Vulnerability Exploitation"),
            ("ValidateAgent",    C["amber"],  "Finding Validation"),
            ("PivotAgent",       C["purple"], "Lateral Movement"),
            ("ReportAgent",      C["green"],  "Report Generation"),
        ]
        for name, color, role in agents:
            row = QWidget()
            row.setStyleSheet(f"background-color: {C['bg3']}; border-radius: 5px;")
            rl = QHBoxLayout(row)
            rl.setContentsMargins(10, 6, 10, 6)
            rl.setSpacing(8)
            dot = QLabel("●")
            dot.setFixedWidth(10)
            dot.setStyleSheet(f"color: {color}; background: transparent; font-size: 8px;")
            rl.addWidget(dot)
            nm = QLabel(name)
            nm.setFont(QFont(MONO, 9, QFont.Weight.Medium))
            nm.setStyleSheet(f"color: {C['text']}; background: transparent;")
            rl.addWidget(nm)
            rl.addStretch()
            desc = QLabel(role)
            desc.setFont(QFont(SANS, 8))
            desc.setStyleSheet(f"color: {C['text3']}; background: transparent;")
            rl.addWidget(desc)
            lay.addWidget(row)

        lay.addStretch()
        return panel

    def _build_main_panel(self) -> QWidget:
        panel = QWidget()
        panel.setStyleSheet(f"background-color: {C['bg']};")
        lay = QVBoxLayout(panel)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        tabs = QTabWidget()
        tabs.addTab(self._build_console_tab(),  "▶  Console")
        tabs.addTab(self._build_lanes_tab(),    "⬡  Lanes")
        tabs.addTab(self._build_commander_tab(),"⬥  Commander (Grok)")
        tabs.addTab(self._build_findings_tab(), "◈  Findings")
        tabs.addTab(self._build_log_tab(),      "≡  Raw Log")
        self._memory_tab = MemoryTab()
        tabs.addTab(self._memory_tab, "🧠  Memory")
        self._tabs = tabs
        lay.addWidget(tabs)
        return panel


    def _build_console_tab(self) -> QWidget:
        """
        Live ops console — every event (log, lane update, finding, commander)
        streams here in a single chronological feed with colour-coded prefixes.
        Includes a filter bar and a pause/resume button.
        """
        w = QWidget()
        w.setStyleSheet(f"background-color: {C['bg']};")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        # ── Top toolbar ──
        toolbar = QWidget()
        toolbar.setFixedHeight(40)
        toolbar.setStyleSheet(
            f"background-color: {C['bg2']}; border-bottom: 1px solid {C['border']};"
        )
        tl = QHBoxLayout(toolbar)
        tl.setContentsMargins(12, 0, 12, 0)
        tl.setSpacing(10)

        # Title
        title_lbl = QLabel("▶  LIVE OPS CONSOLE")
        title_lbl.setFont(QFont(SANS, 10, QFont.Weight.Bold))
        title_lbl.setStyleSheet(f"color: {C['green']}; letter-spacing: 2px; background: transparent;")
        tl.addWidget(title_lbl)

        # Filter chips
        self._console_filters = {}
        filter_specs = [
            ("ALL",   None,         C["text2"]),
            ("CMD",   "CMD",        C["cyan"]),
            ("TOOL",  "TOOL",       C["accent"]),
            ("FIND",  "FIND",       C["red"]),
            ("OK",    "OK",         C["green"]),
            ("WARN",  "WARN",       C["amber"]),
            ("ERR",   "ERR",        C["red"]),
        ]
        self._console_filter_active = "ALL"
        for label, key, color in filter_specs:
            btn = QPushButton(label)
            btn.setFixedHeight(24)
            btn.setFixedWidth(52)
            btn.setFont(QFont(SANS, 8, QFont.Weight.Bold))
            btn.setCheckable(True)
            btn.setChecked(label == "ALL")
            btn.setStyleSheet(f"""
                QPushButton {{
                    background: transparent; color: {C['text3']};
                    border: 1px solid {C['border']};
                    border-radius: 3px;
                }}
                QPushButton:checked {{
                    background: rgba(255,255,255,0.05);
                    color: {color};
                    border-color: {color};
                }}
                QPushButton:hover {{ color: {C['text2']}; }}
            """)
            btn.clicked.connect(lambda checked, k=label: self._set_console_filter(k))
            tl.addWidget(btn)
            self._console_filters[label] = btn

        tl.addStretch()

        # Event counter
        self._console_event_count = QLabel("0 events")
        self._console_event_count.setFont(QFont(MONO, 9))
        self._console_event_count.setStyleSheet(f"color: {C['text3']}; background: transparent;")
        tl.addWidget(self._console_event_count)

        # Pause button
        self._console_paused = False
        self._console_pause_btn = QPushButton("⏸  Pause")
        self._console_pause_btn.setFixedHeight(24)
        self._console_pause_btn.setFont(QFont(SANS, 8, QFont.Weight.Medium))
        self._console_pause_btn.setStyleSheet(f"""
            QPushButton {{
                background: {C['bg4']}; color: {C['text2']};
                border: 1px solid {C['border2']}; border-radius: 3px; padding: 0 10px;
            }}
            QPushButton:hover {{ color: {C['text']}; }}
        """)
        self._console_pause_btn.clicked.connect(self._toggle_console_pause)
        tl.addWidget(self._console_pause_btn)

        # Clear button
        clear_btn = QPushButton("✕  Clear")
        clear_btn.setFixedHeight(24)
        clear_btn.setFont(QFont(SANS, 8, QFont.Weight.Medium))
        clear_btn.setStyleSheet(f"""
            QPushButton {{
                background: {C['bg4']}; color: {C['text3']};
                border: 1px solid {C['border']}; border-radius: 3px; padding: 0 10px;
            }}
            QPushButton:hover {{ color: {C['red']}; border-color: {C['red']}; }}
        """)
        clear_btn.clicked.connect(self._clear_console)
        tl.addWidget(clear_btn)

        lay.addWidget(toolbar)

        # ── Console output ──
        self.console_view = QTextEdit()
        self.console_view.setReadOnly(True)
        self.console_view.setFont(QFont(MONO, 10))
        self.console_view.setLineWrapMode(QTextEdit.LineWrapMode.NoWrap)
        self.console_view.setStyleSheet(
            f"background-color: #060a10; color: {C['text']}; border: none; padding: 12px;"
        )
        self.console_view.setPlaceholderText(
            "Waiting for campaign…\n\n"
            "Every tool command, finding, lane state change, and Grok message\n"
            "will stream here in real time."
        )
        lay.addWidget(self.console_view)

        # ── Bottom status strip ──
        strip = QWidget()
        strip.setFixedHeight(24)
        strip.setStyleSheet(f"background-color: {C['bg2']}; border-top: 1px solid {C['border']};")
        sl = QHBoxLayout(strip)
        sl.setContentsMargins(12, 0, 12, 0)
        sl.setSpacing(16)

        self._console_lane_indicator = QLabel("No active lanes")
        self._console_lane_indicator.setFont(QFont(MONO, 8))
        self._console_lane_indicator.setStyleSheet(f"color: {C['text3']}; background: transparent;")
        sl.addWidget(self._console_lane_indicator)
        sl.addStretch()

        self._console_last_tool = QLabel("")
        self._console_last_tool.setFont(QFont(MONO, 8))
        self._console_last_tool.setStyleSheet(f"color: {C['text3']}; background: transparent;")
        sl.addWidget(self._console_last_tool)

        lay.addWidget(strip)

        self._console_line_count = 0
        self._console_buffer = []  # holds (prefix_key, html_line) for filter replay

        return w

    def _set_console_filter(self, key: str):
        self._console_filter_active = key
        for label, btn in self._console_filters.items():
            btn.setChecked(label == key)
        # Replay buffer with new filter
        self.console_view.clear()
        for entry_key, html in self._console_buffer[-2000:]:
            if key == "ALL" or entry_key == key:
                self.console_view.append(html)
        self.console_view.verticalScrollBar().setValue(
            self.console_view.verticalScrollBar().maximum()
        )

    def _toggle_console_pause(self):
        self._console_paused = not self._console_paused
        if self._console_paused:
            self._console_pause_btn.setText("▶  Resume")
            self._console_pause_btn.setStyleSheet(f"""
                QPushButton {{
                    background: rgba(16,185,129,0.15); color: {C['green']};
                    border: 1px solid {C['green']}; border-radius: 3px; padding: 0 10px;
                }}
            """)
        else:
            self._console_pause_btn.setText("⏸  Pause")
            self._console_pause_btn.setStyleSheet(f"""
                QPushButton {{
                    background: {C['bg4']}; color: {C['text2']};
                    border: 1px solid {C['border2']}; border-radius: 3px; padding: 0 10px;
                }}
            """)
            # Flush any buffered lines
            self._set_console_filter(self._console_filter_active)

    def _clear_console(self):
        self.console_view.clear()
        self._console_buffer.clear()
        self._console_line_count = 0
        self._console_event_count.setText("0 events")

    def _console_write(self, prefix_key: str, prefix_label: str,
                       color: str, message: str, dim: bool = False):
        """
        Core write method. All console output goes through here.
        prefix_key  — used for filtering: CMD/TOOL/FIND/OK/WARN/ERR/INFO
        prefix_label — displayed badge text
        color       — hex colour for the badge
        message     — the message content
        dim         — if True, render in muted text3 colour
        """
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        msg_color = C["text3"] if dim else C["text"]

        # Escape HTML special chars
        safe_msg = (message
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;"))

        html = (
            f'<span style="color:{C['text3']}">[{ts}]</span> '
            f'<span style="color:{color};font-weight:bold"> {prefix_label:<6}</span> '
            f'<span style="color:{msg_color}"> {safe_msg}</span>'
        )

        self._console_buffer.append((prefix_key, html))
        if len(self._console_buffer) > 5000:
            self._console_buffer = self._console_buffer[-4000:]

        self._console_line_count += 1
        self._console_event_count.setText(f"{self._console_line_count} events")

        if not self._console_paused:
            if self._console_filter_active == "ALL" or self._console_filter_active == prefix_key:
                self.console_view.append(html)
                self.console_view.verticalScrollBar().setValue(
                    self.console_view.verticalScrollBar().maximum()
                )

    def _build_lanes_tab(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet(f"background-color: {C['bg']};")
        outer = QVBoxLayout(w)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { border: none; background: transparent; }")

        inner = QWidget()
        inner.setStyleSheet("background: transparent;")
        self.lanes_layout = QVBoxLayout(inner)
        self.lanes_layout.setContentsMargins(16, 16, 16, 16)
        self.lanes_layout.setSpacing(10)
        self.lanes_layout.setAlignment(Qt.AlignmentFlag.AlignTop)

        placeholder = QLabel("No active lanes — launch a campaign to begin.")
        placeholder.setFont(QFont(SANS, 11))
        placeholder.setStyleSheet(f"color: {C['text3']}; background: transparent;")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lanes_layout.addWidget(placeholder)
        self._lanes_placeholder = placeholder
        self._placeholder_visible = True  # track state without touching C++ object

        scroll.setWidget(inner)
        outer.addWidget(scroll)
        return w

    def _build_commander_tab(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet(f"background-color: {C['bg']};")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)

        header = QWidget()
        header.setFixedHeight(40)
        header.setStyleSheet(f"background-color: {C['bg2']}; border-bottom: 1px solid {C['border']};")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(16, 0, 16, 0)
        grok_lbl = QLabel("⬥  GROK ORCHESTRATOR  ·  Tactical Feed")
        grok_lbl.setFont(QFont(SANS, 10, QFont.Weight.Bold))
        grok_lbl.setStyleSheet(f"color: {C['accent']}; letter-spacing: 1px; background: transparent;")
        hl.addWidget(grok_lbl)
        hl.addStretch()
        model_lbl = QLabel("grok-3")
        model_lbl.setFont(QFont(MONO, 9))
        model_lbl.setStyleSheet(f"color: {C['text3']}; background: transparent;")
        hl.addWidget(model_lbl)
        lay.addWidget(header)

        self.commander_view = QTextEdit()
        self.commander_view.setReadOnly(True)
        self.commander_view.setFont(QFont(MONO, 10))
        self.commander_view.setStyleSheet(
            f"background-color: {C['bg']}; color: {C['cyan']}; border: none; padding: 16px;"
        )
        self.commander_view.setPlaceholderText(
            "Grok will narrate the campaign here in real-time…\n\n"
            "Enter your xAI API key and launch a campaign to begin."
        )
        lay.addWidget(self.commander_view)
        return w

    def _build_findings_tab(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet(f"background-color: {C['bg2']};")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)

        splitter = QSplitter(Qt.Orientation.Vertical)

        self.findings_table = QTableWidget()
        self.findings_table.setColumnCount(6)
        self.findings_table.setHorizontalHeaderLabels(["ID", "Type", "Title", "Severity", "Agent", "Time"])
        self.findings_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.findings_table.verticalHeader().setVisible(False)
        self.findings_table.setAlternatingRowColors(True)
        self.findings_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.findings_table.cellClicked.connect(self._on_finding_clicked)
        splitter.addWidget(self.findings_table)

        self.finding_detail = QTextEdit()
        self.finding_detail.setReadOnly(True)
        self.finding_detail.setMaximumHeight(200)
        self.finding_detail.setPlaceholderText("Click a finding to view details…")
        splitter.addWidget(self.finding_detail)

        splitter.setSizes([400, 180])
        lay.addWidget(splitter)
        return w

    def _build_log_tab(self) -> QWidget:
        w = QWidget()
        w.setStyleSheet(f"background-color: {C['bg']};")
        lay = QVBoxLayout(w)
        lay.setContentsMargins(0, 0, 0, 0)
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont(MONO, 9))
        LogHighlighter(self.log_view.document())
        lay.addWidget(self.log_view)
        return w

    # ── Campaign Control ──────────────────────────────────────────────────────

    def _on_api_key_changed(self, key: str):
        if key.startswith("xai-") and len(key) > 20:
            self._grok_status.setText("● Grok: key configured")
            self._grok_status.setStyleSheet(f"color: {C['green']}; background: transparent;")
            if hasattr(self, '_memory_tab'):
                self._memory_tab.set_api_key(key)
        else:
            self._grok_status.setText("● Grok: not connected")
            self._grok_status.setStyleSheet(f"color: {C['text3']}; background: transparent;")

    def _launch_campaign(self):
        api_key = self.api_key_input.text().strip()
        target  = self.target_input.text().strip()

        if not api_key:
            QMessageBox.warning(self, "API Key Required",
                "Enter your xAI Grok API key before launching.\n\nGet one at: console.x.ai")
            return
        if not target:
            QMessageBox.warning(self, "Target Required", "Enter a target IP, range, or domain.")
            return

        # Clear previous campaign state
        while self.lanes_layout.count():
            item = self.lanes_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self.lane_cards.clear()
        # Rebuild placeholder safely
        placeholder = QLabel("No active lanes — launch a campaign to begin.")
        placeholder.setFont(QFont(SANS, 11))
        placeholder.setStyleSheet(f"color: {C['text3']}; background: transparent;")
        placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lanes_layout.addWidget(placeholder)
        self._lanes_placeholder = placeholder
        self._placeholder_visible = True
        self.findings_table.setRowCount(0)
        self._finding_details.clear()
        self._shown_finding_ids.clear()
        self.commander_view.clear()
        self.log_view.clear()

        objective  = self.objective_combo.currentText()
        opsec_mode = self.opsec_combo.currentData() or "stealth"
        max_lanes  = int(self.lanes_combo.currentText())

        self._runner = CampaignRunner(
            api_key    = api_key,
            target     = target,
            objective  = objective,
            opsec_mode = opsec_mode,
            max_lanes  = max_lanes,
        )

        self._runner.log_signal.connect(self._append_log)
        self._runner.lane_update_signal.connect(self._update_lane_card)
        self._runner.finding_signal.connect(self._add_finding)
        self._runner.commander_signal.connect(self._append_commander)
        self._runner.complete_signal.connect(self._on_campaign_complete)

        self.launch_btn.setEnabled(False)
        self.abort_btn.setEnabled(True)
        self.campaign_start_time = datetime.now()
        self._elapsed = 0
        self._clock_timer.start(1000)

        self._runner.start()
        self._status.showMessage(f"Campaign running — target: {target}  ·  opsec: {opsec_mode.upper()}")
        self._append_log(f"Campaign launched — target: {target}", "info")

    def _abort_campaign(self):
        if self._runner:
            self._runner.abort()
        self.abort_btn.setEnabled(False)
        self._clock_timer.stop()
        self._status.showMessage("Aborting…")

    def _on_campaign_complete(self):
        self.launch_btn.setEnabled(True)
        self.abort_btn.setEnabled(False)
        self._clock_timer.stop()
        self._status.showMessage("Campaign complete.")
        self._append_log("Campaign complete.", "success")

    # ── Signal Handlers ───────────────────────────────────────────────────────

    def _append_commander(self, text: str):
        # Stream commander output to console too
        for line in text.splitlines():
            if line.strip():
                self._console_write("CMD", "CMD", C["cyan"], line, dim=False)
        self.commander_view.append(text)
        self.commander_view.append("")  # spacer
        self.commander_view.verticalScrollBar().setValue(
            self.commander_view.verticalScrollBar().maximum()
        )

    def _append_log(self, message: str, level: str = "info"):
        # ── Console routing ──
        level_map = {
            "info":    ("INFO", C["text2"],  True),
            "success": ("OK",   C["green"],  False),
            "warning": ("WARN", C["amber"],  False),
            "error":   ("ERR",  C["red"],    False),
        }
        if "[Commander]" in message:
            self._console_write("CMD", "CMD", C["cyan"], message, dim=False)
        elif "▶" in message or "Running:" in message or "nmap" in message.lower() or              any(t in message for t in ("nuclei","sqlmap","ffuf","hydra","crackmapexec",
                                        "nikto","whatweb","amass","subfinder","impacket")):
            self._console_write("TOOL", "TOOL", C["accent"], message, dim=False)
            self._console_last_tool.setText(message[:80])
        else:
            prefix_key, color, dim = level_map.get(level, ("INFO", C["text2"], True))
            self._console_write(prefix_key, prefix_key, color, message, dim=dim)

        # ── Raw log ──
        if message == self._last_log_message:
            self._last_log_count += 1
            cursor = self.log_view.textCursor()
            cursor.movePosition(QTextCursor.MoveOperation.End)
            cursor.movePosition(QTextCursor.MoveOperation.StartOfBlock, QTextCursor.MoveMode.KeepAnchor)
            cursor.removeSelectedText()
            cursor.insertText(f"{message} (×{self._last_log_count})")
        else:
            self._last_log_message = message
            self._last_log_count   = 1
            ts    = datetime.now().strftime("%H:%M:%S")
            badge = {"info": "INFO  ", "success": "OK    ", "warning": "WARN  ", "error": "ERROR "}.get(level, "INFO  ")
            if "[Commander]" in message:
                badge = "CMD   "
            self.log_view.append(f"[{ts}]  {badge}  {message}")
        self.log_view.verticalScrollBar().setValue(self.log_view.verticalScrollBar().maximum())

    def _update_lane_card(self, lane_id: str, state: str, agent: str, progress: int, budget: int):
        if self._placeholder_visible:
            try:
                self._lanes_placeholder.hide()
            except RuntimeError:
                pass
            self._placeholder_visible = False

        if lane_id not in self.lane_cards:
            card = LaneCard(lane_id, self.target_input.text() or "unknown")
            self.lane_cards[lane_id] = card
            self.lanes_layout.addWidget(card)

        self.lane_cards[lane_id].update_state(state, agent, progress, budget)
        self.lane_cards[lane_id].add_log_entry(f"{agent}: {state}")
        self._metrics.update("OpSec Budget", f"{budget}%")

        active = sum(1 for c in self.lane_cards.values()
                     if c._state_lbl.text() not in ("COMPLETE", "ERROR", "IDLE"))
        self._metrics.update("Active Lanes", str(active))

        # Console lane state change
        state_colors = {
            "PLANNING":  C["accent"], "EXECUTING": C["active"],
            "COMPLETE":  C["green"],  "ERROR":     C["red"],
            "WAITING":   C["amber"],
        }
        sc = state_colors.get(state, C["text2"])
        self._console_write(
            "INFO", "LANE", sc,
            f"{lane_id}  {state:<12}  agent={agent or'—'}  progress={progress}%  opsec={budget}%",
            dim=(state in ("IDLE","WAITING")),
        )
        lane_summary = "  ".join(
            f"{lid}:{c._state_lbl.text()}"
            for lid, c in self.lane_cards.items()
        )
        self._console_lane_indicator.setText(lane_summary[:120])

    def _on_finding_clicked(self, row, col):
        id_item = self.findings_table.item(row, 0)
        if id_item:
            fid    = id_item.text()
            detail = self._finding_details.get(fid, "")
            if detail:
                import json
                try:
                    detail = json.dumps(json.loads(detail), indent=2)
                except Exception:
                    pass
                self.finding_detail.setFont(QFont(MONO, 9))
                self.finding_detail.setPlainText(detail)

    def _add_finding(self, finding: dict):
        SEV_STYLE = {
            "critical": ("#7f1d1d", "#fca5a5"),
            "high":     ("#7c2d12", "#fdba74"),
            "medium":   ("#78350f", "#fde68a"),
            "low":      ("#14532d", "#86efac"),
            "info":     ("#0c2340", "#7dd3fc"),
        }
        t   = self.findings_table
        row = t.rowCount()
        t.insertRow(row)
        t.setRowHeight(row, 36)
        severity = finding.get("severity", "info").lower()
        fid      = str(finding.get("id", row))
        raw_ts   = str(finding.get("timestamp", datetime.now().isoformat()))
        ts       = raw_ts[:19].replace("T", " ")

        items = [
            QTableWidgetItem(fid),
            QTableWidgetItem(finding.get("finding_type", "unknown")),
            QTableWidgetItem(finding.get("title", "")),
            QTableWidgetItem(severity.upper()),
            QTableWidgetItem(finding.get("agent", "")),
            QTableWidgetItem(ts),
        ]
        bg, fg = SEV_STYLE.get(severity, ("#1a2035", "#7a869e"))
        items[3].setBackground(QColor(bg))
        items[3].setForeground(QColor(fg))
        items[3].setTextAlignment(Qt.AlignmentFlag.AlignCenter)

        for col, item in enumerate(items):
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            t.setItem(row, col, item)
        t.scrollToBottom()

        if finding.get("detail"):
            self._finding_details[fid] = finding["detail"]

        self._metrics.update("Findings", str(t.rowCount()))
        crits = sum(1 for r in range(t.rowCount())
                    if t.item(r, 3) and t.item(r, 3).text() in ("CRITICAL", "HIGH"))
        self._metrics.update("Exploitable", str(crits))

        # Console finding notification
        sev_colors = {
            "critical": C["red"], "high": C["red"],
            "medium": C["amber"], "low": C["green"], "info": C["text3"],
        }
        fc = sev_colors.get(severity, C["text2"])
        self._console_write(
            "FIND", "FIND", fc,
            f"[{severity.upper():<8}] {finding.get('title','')}  —  {finding.get('target','')}",
            dim=False,
        )

    def _update_stats(self, stats: dict):
        for k, v in stats.items():
            self._metrics.update(k, str(v))

    def _tick_clock(self):
        self._elapsed += 1
        m, s = divmod(self._elapsed, 60)
        h, m = divmod(m, 60)
        txt = f"{h:02d}:{m:02d}:{s:02d}"
        self._clock_lbl.setText(txt)
        self._metrics.update("Campaign Time", f"{m:02d}:{s:02d}")


# ─── Entry Point ──────────────────────────────────────────────────────────────
def main():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    app.setFont(QFont(SANS, 10))
    window = HiveReaperMainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
