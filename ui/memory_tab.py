"""
HiveReaper v2 — Memory & Training UI Tab
"""
import asyncio
import json
from datetime import datetime
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QLineEdit, QComboBox, QTextEdit, QTableWidget, QTableWidgetItem,
    QHeaderView, QSplitter, QFrame, QTabWidget, QInputDialog,
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor

C = {
    "bg":"#090d13","bg2":"#0d1119","bg3":"#111621","bg4":"#161b27",
    "border":"#1e2535","border2":"#28304a","border3":"#333d58",
    "text":"#dde3f0","text2":"#7a869e","text3":"#3d4a62",
    "accent":"#3b82f6","cyan":"#06b6d4","green":"#10b981",
    "amber":"#f59e0b","red":"#ef4444","purple":"#8b5cf6",
}
MONO = "JetBrains Mono, Cascadia Code, Fira Code, Consolas, monospace"
SANS = "Inter, Segoe UI, Helvetica Neue, sans-serif"


class TrainingRunner(QThread):
    log_signal      = pyqtSignal(str, str)
    finding_signal  = pyqtSignal(dict)
    flag_signal     = pyqtSignal(str)
    complete_signal = pyqtSignal(dict)

    def __init__(self, api_key, box_name, target_ip, difficulty, category, hint, parent=None):
        super().__init__(parent)
        self.api_key=api_key; self.box_name=box_name; self.target_ip=target_ip
        self.difficulty=difficulty; self.category=category; self.hint=hint
        self._trainer = None

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        from training.thm_trainer import THMTrainer
        self._trainer = THMTrainer(
            api_key    = self.api_key,
            on_log     = lambda m,l: self.log_signal.emit(m,l),
            on_finding = lambda f: self.finding_signal.emit(f),
            on_flag    = lambda f: self.flag_signal.emit(f),
            on_complete= lambda: None,
        )
        try:
            result = loop.run_until_complete(self._trainer.run_box(
                box_name=self.box_name, target_ip=self.target_ip,
                difficulty=self.difficulty, category=self.category, hint=self.hint,
            ))
            self.complete_signal.emit(result)
        except Exception as e:
            self.log_signal.emit(f"Training error: {e}", "error")
            self.complete_signal.emit({})
        finally:
            loop.close()


class MemoryTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._api_key = ""
        self._runner  = None
        self._flags   = []
        self._setup_ui()
        self._refresh_stats()

    def set_api_key(self, key: str):
        self._api_key = key

    def _setup_ui(self):
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0,0,0,0)
        inner = QTabWidget()
        inner.addTab(self._build_training_tab(), "⚔  THM Training")
        inner.addTab(self._build_episodes_tab(), "📋  Episodes")
        inner.addTab(self._build_patterns_tab(), "⚡  Patterns")
        inner.addTab(self._build_stats_tab(),    "📊  Stats")
        lay.addWidget(inner)

    def _mk_section(self, text):
        lbl = QLabel(text.upper())
        lbl.setFont(QFont(SANS,8,QFont.Weight.Bold))
        lbl.setStyleSheet(f"color:{C['text3']};letter-spacing:2px;background:transparent;padding:8px 0 4px 0;")
        return lbl

    def _build_training_tab(self):
        w = QWidget(); w.setStyleSheet(f"background:{C['bg']};")
        lay = QVBoxLayout(w); lay.setContentsMargins(20,20,20,20); lay.setSpacing(10)

        hdr = QLabel("⚔  TRYHACKME / HTB TRAINING MODE")
        hdr.setFont(QFont(SANS,13,QFont.Weight.Bold))
        hdr.setStyleSheet(f"color:{C['text']};letter-spacing:2px;background:transparent;")
        lay.addWidget(hdr)

        sub = QLabel(
            "Run the full swarm against a CTF box. Every campaign is recorded — "
            "flags captured, attack path saved, patterns extracted. "
            "The swarm gets smarter with every box you run."
        )
        sub.setWordWrap(True); sub.setFont(QFont(SANS,10))
        sub.setStyleSheet(f"color:{C['text2']};background:transparent;")
        lay.addWidget(sub)

        div = QFrame(); div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet(f"border:none;border-top:1px solid {C['border']};background:transparent;")
        lay.addWidget(div)

        form = QWidget()
        form.setStyleSheet(f"background:{C['bg2']};border:1px solid {C['border2']};border-radius:8px;")
        fl = QVBoxLayout(form); fl.setContentsMargins(18,14,18,14); fl.setSpacing(8)

        def row(label, widget):
            r = QHBoxLayout()
            l = QLabel(label); l.setFixedWidth(130)
            l.setFont(QFont(SANS,10)); l.setStyleSheet(f"color:{C['text2']};background:transparent;")
            r.addWidget(l); r.addWidget(widget, stretch=1); fl.addLayout(r)

        self._t_box   = QLineEdit(); self._t_box.setPlaceholderText("e.g. Blue, Mr Robot, Relevant")
        self._t_ip    = QLineEdit(); self._t_ip.setPlaceholderText("e.g. 10.10.10.40")
        self._t_diff  = QComboBox()
        for d in ["easy","medium","hard","insane"]: self._t_diff.addItem(d.title(), d)
        self._t_cat   = QComboBox()
        for c in ["linux","windows","web","network","crypto","misc"]: self._t_cat.addItem(c.title(), c)
        self._t_hint  = QLineEdit(); self._t_hint.setPlaceholderText("Optional tip e.g. 'Check SMB, try MS17-010'")

        row("Box Name",      self._t_box)
        row("Target IP",     self._t_ip)
        row("Difficulty",    self._t_diff)
        row("Category",      self._t_cat)
        row("Hint (optional)", self._t_hint)
        lay.addWidget(form)

        btns = QHBoxLayout()
        self._t_launch = QPushButton("▶  Start Training Session")
        self._t_launch.setFixedHeight(38); self._t_launch.setFont(QFont(SANS,10,QFont.Weight.Bold))
        self._t_launch.setStyleSheet(f"QPushButton{{background:{C['accent']};color:#fff;border:none;border-radius:6px;padding:0 20px;}}QPushButton:hover{{background:#1d4ed8;}}QPushButton:disabled{{background:{C['bg4']};color:{C['text3']};}}")
        self._t_launch.clicked.connect(self._launch_training)
        btns.addWidget(self._t_launch)

        self._t_hint_btn = QPushButton("💡  Give Hint")
        self._t_hint_btn.setFixedHeight(38); self._t_hint_btn.setEnabled(False)
        self._t_hint_btn.setFont(QFont(SANS,10))
        self._t_hint_btn.setStyleSheet(f"QPushButton{{background:{C['bg4']};color:{C['amber']};border:1px solid {C['amber']}44;border-radius:6px;padding:0 14px;}}QPushButton:disabled{{color:{C['text3']};border-color:{C['border']};}}")
        self._t_hint_btn.clicked.connect(self._give_hint)
        btns.addWidget(self._t_hint_btn)
        lay.addLayout(btns)

        flag_box = QWidget()
        flag_box.setStyleSheet(f"background:{C['bg3']};border:1px solid {C['border2']};border-radius:6px;")
        fbl = QVBoxLayout(flag_box); fbl.setContentsMargins(14,8,14,8); fbl.setSpacing(2)
        fl2 = QLabel("🚩 FLAGS CAPTURED"); fl2.setFont(QFont(SANS,9,QFont.Weight.Bold))
        fl2.setStyleSheet(f"color:{C['text3']};letter-spacing:2px;background:transparent;")
        fbl.addWidget(fl2)
        self._flag_lbl = QLabel("None yet"); self._flag_lbl.setFont(QFont(MONO,11))
        self._flag_lbl.setStyleSheet(f"color:{C['green']};background:transparent;")
        self._flag_lbl.setWordWrap(True); fbl.addWidget(self._flag_lbl)
        lay.addWidget(flag_box)

        self._t_log = QTextEdit(); self._t_log.setReadOnly(True)
        self._t_log.setFont(QFont(MONO,9))
        self._t_log.setStyleSheet(f"background:#060a10;color:{C['text2']};border:none;padding:10px;")
        self._t_log.setPlaceholderText("Training output streams here…")
        lay.addWidget(self._t_log, stretch=1)
        return w

    def _build_episodes_tab(self):
        w = QWidget(); w.setStyleSheet(f"background:{C['bg2']};")
        lay = QVBoxLayout(w); lay.setContentsMargins(0,0,0,0)

        tb = QWidget(); tb.setFixedHeight(40)
        tb.setStyleSheet(f"background:{C['bg2']};border-bottom:1px solid {C['border']};")
        tbl = QHBoxLayout(tb); tbl.setContentsMargins(12,0,12,0)
        tbl.addWidget(self._mk_section("Episode History"))
        tbl.addStretch()
        rb = QPushButton("↻ Refresh"); rb.setFixedHeight(26)
        rb.setStyleSheet(f"QPushButton{{background:{C['bg4']};color:{C['text2']};border:1px solid {C['border2']};border-radius:4px;padding:0 10px;}}")
        rb.clicked.connect(self._refresh_episodes); tbl.addWidget(rb)
        lay.addWidget(tb)

        self._ep_table = QTableWidget()
        self._ep_table.setColumnCount(8)
        self._ep_table.setHorizontalHeaderLabels(["Target","Type","Source","Outcome","Flags","Duration","Findings","Date"])
        self._ep_table.horizontalHeader().setSectionResizeMode(0,QHeaderView.ResizeMode.Stretch)
        self._ep_table.verticalHeader().setVisible(False)
        self._ep_table.setAlternatingRowColors(True)
        self._ep_table.setStyleSheet(f"QTableWidget{{background:{C['bg2']};color:{C['text']};border:none;font-size:11px;font-family:{MONO};}}QHeaderView::section{{background:{C['bg3']};color:{C['text2']};padding:6px 8px;border:none;border-bottom:1px solid {C['border2']};font-size:10px;font-weight:600;}}QTableWidget::item{{padding:4px 8px;border-bottom:1px solid {C['border']};}}")
        self._ep_table.cellClicked.connect(self._on_ep_click)
        lay.addWidget(self._ep_table, stretch=1)

        self._ep_detail = QTextEdit(); self._ep_detail.setReadOnly(True)
        self._ep_detail.setMaximumHeight(160); self._ep_detail.setFont(QFont(MONO,9))
        self._ep_detail.setStyleSheet(f"background:{C['bg']};color:{C['text2']};border:none;padding:10px;")
        self._ep_detail.setPlaceholderText("Click an episode for details…")
        lay.addWidget(self._ep_detail)
        self._refresh_episodes()
        return w

    def _build_patterns_tab(self):
        w = QWidget(); w.setStyleSheet(f"background:{C['bg2']};")
        lay = QVBoxLayout(w); lay.setContentsMargins(0,0,0,0)

        tb = QWidget(); tb.setFixedHeight(40)
        tb.setStyleSheet(f"background:{C['bg2']};border-bottom:1px solid {C['border']};")
        tbl = QHBoxLayout(tb); tbl.setContentsMargins(12,0,12,0)
        tbl.addWidget(self._mk_section("Learned Attack Patterns"))
        tbl.addStretch()
        rb = QPushButton("↻ Refresh"); rb.setFixedHeight(26)
        rb.setStyleSheet(f"QPushButton{{background:{C['bg4']};color:{C['text2']};border:1px solid {C['border2']};border-radius:4px;padding:0 10px;}}")
        rb.clicked.connect(self._refresh_patterns); tbl.addWidget(rb)
        lay.addWidget(tb)

        self._pat_table = QTableWidget()
        self._pat_table.setColumnCount(5)
        self._pat_table.setHorizontalHeaderLabels(["Signal","Action","CVE","Hits","Type"])
        self._pat_table.horizontalHeader().setSectionResizeMode(1,QHeaderView.ResizeMode.Stretch)
        self._pat_table.verticalHeader().setVisible(False)
        self._pat_table.setAlternatingRowColors(True)
        self._pat_table.setStyleSheet(f"QTableWidget{{background:{C['bg2']};color:{C['text']};border:none;font-size:11px;font-family:{MONO};}}QHeaderView::section{{background:{C['bg3']};color:{C['text2']};padding:6px 8px;border:none;border-bottom:1px solid {C['border2']};font-size:10px;font-weight:600;}}QTableWidget::item{{padding:4px 8px;border-bottom:1px solid {C['border']};}}")
        lay.addWidget(self._pat_table, stretch=1)
        self._refresh_patterns()
        return w

    def _build_stats_tab(self):
        w = QWidget(); w.setStyleSheet(f"background:{C['bg']};")
        lay = QVBoxLayout(w); lay.setContentsMargins(24,24,24,24); lay.setSpacing(16)

        hdr = QLabel("MEMORY STATISTICS")
        hdr.setFont(QFont(SANS,12,QFont.Weight.Bold))
        hdr.setStyleSheet(f"color:{C['text']};letter-spacing:3px;background:transparent;")
        lay.addWidget(hdr)

        box = QWidget()
        box.setStyleSheet(f"background:{C['bg2']};border:1px solid {C['border2']};border-radius:8px;")
        bl = QVBoxLayout(box); bl.setContentsMargins(20,16,20,16); bl.setSpacing(8)
        self._stat_lbls: dict[str,QLabel] = {}
        for key,label,color in [
            ("episodes","Total Episodes",C["text"]),
            ("successes","Successful Campaigns",C["green"]),
            ("thm_boxes","THM / HTB Boxes Solved",C["cyan"]),
            ("live_engagements","Live Engagements",C["accent"]),
            ("patterns","Attack Patterns Learned",C["amber"]),
            ("strategies","Strategies Learned",C["purple"]),
            ("hints","Operator Hints Recorded",C["text2"]),
        ]:
            r = QHBoxLayout()
            l = QLabel(label); l.setFont(QFont(SANS,10))
            l.setStyleSheet(f"color:{C['text2']};background:transparent;")
            r.addWidget(l); r.addStretch()
            v = QLabel("—"); v.setFont(QFont(MONO,13,QFont.Weight.Bold))
            v.setStyleSheet(f"color:{color};background:transparent;")
            r.addWidget(v); bl.addLayout(r)
            self._stat_lbls[key] = v
        lay.addWidget(box)

        rb = QPushButton("↻  Refresh")
        rb.setFixedHeight(36); rb.setFont(QFont(SANS,10))
        rb.setStyleSheet(f"QPushButton{{background:{C['bg4']};color:{C['text2']};border:1px solid {C['border2']};border-radius:6px;padding:0 16px;}}QPushButton:hover{{color:{C['text']};}}")
        rb.clicked.connect(self._refresh_stats)
        lay.addWidget(rb); lay.addStretch()
        return w

    # ── Data refresh ──────────────────────────────────────────────────────────

    def _refresh_stats(self):
        try:
            from memory.experience_store import ExperienceStore
            s = ExperienceStore(); st = s.get_stats(); s.close()
            for k,lbl in self._stat_lbls.items():
                lbl.setText(str(st.get(k,0)))
        except Exception: pass

    def _refresh_episodes(self):
        try:
            from memory.experience_store import ExperienceStore
            s = ExperienceStore(); eps = s.get_all_episodes(100); s.close()
            t = self._ep_table; t.setRowCount(0)
            for ep in eps:
                row = t.rowCount(); t.insertRow(row); t.setRowHeight(row,30)
                flags = json.loads(ep.get("flags_found","[]"))
                finds = json.loads(ep.get("findings_json","[]"))
                dur   = ep.get("duration_secs",0)
                oc    = ep.get("outcome","?")
                oc_c  = C["green"] if oc=="success" else C["amber"] if oc=="partial" else C["red"]
                items = [
                    QTableWidgetItem(ep.get("target","")),
                    QTableWidgetItem(ep.get("target_type","")),
                    QTableWidgetItem(ep.get("source","").upper()),
                    QTableWidgetItem(oc.upper()),
                    QTableWidgetItem(str(len(flags))),
                    QTableWidgetItem(f"{dur//60}m{dur%60}s" if dur else "—"),
                    QTableWidgetItem(str(len(finds))),
                    QTableWidgetItem(ep.get("timestamp","")[:10]),
                ]
                items[3].setForeground(QColor(oc_c))
                for col,item in enumerate(items):
                    item.setFlags(item.flags()&~Qt.ItemFlag.ItemIsEditable)
                    item.setData(Qt.ItemDataRole.UserRole,ep)
                    t.setItem(row,col,item)
        except Exception: pass

    def _refresh_patterns(self):
        try:
            from memory.experience_store import ExperienceStore
            s = ExperienceStore(); pats = s.get_all_patterns(); s.close()
            t = self._pat_table; t.setRowCount(0)
            for p in pats:
                row = t.rowCount(); t.insertRow(row); t.setRowHeight(row,30)
                hits = p.get("success_count",1)
                items = [
                    QTableWidgetItem(p.get("signal","")[:50]),
                    QTableWidgetItem(p.get("action","")[:80]),
                    QTableWidgetItem(p.get("cve_id","") or "—"),
                    QTableWidgetItem(str(hits)),
                    QTableWidgetItem(p.get("signal_type","") or "—"),
                ]
                items[3].setForeground(QColor(C["green"] if hits>=3 else C["amber"] if hits>=2 else C["text2"]))
                for col,item in enumerate(items):
                    item.setFlags(item.flags()&~Qt.ItemFlag.ItemIsEditable)
                    t.setItem(row,col,item)
        except Exception: pass

    def _on_ep_click(self, row, col):
        item = self._ep_table.item(row,0)
        if not item: return
        ep = item.data(Qt.ItemDataRole.UserRole)
        if not ep: return
        path    = json.loads(ep.get("attack_path","[]"))
        lessons = ep.get("lessons","")
        tags    = json.loads(ep.get("tags","[]"))
        flags   = json.loads(ep.get("flags_found","[]"))
        text = (f"Target:  {ep.get('target','')}\n"
                f"Source:  {ep.get('source','').upper()}  ·  {ep.get('target_type','')}\n"
                f"Outcome: {ep.get('outcome','')}\n"
                f"Tags:    {', '.join(tags)}\n"
                f"Flags:   {flags or 'none'}\n\n"
                f"Lessons:\n{lessons}\n\n"
                f"Attack Path ({len(path)} steps):\n")
        for i,step in enumerate(path[:20],1):
            text += f"  {i:2d}. {step.get('step','')[:100]}\n"
        self._ep_detail.setPlainText(text)

    # ── Training control ──────────────────────────────────────────────────────

    def _launch_training(self):
        if not self._api_key:
            self._t_log.append('<span style="color:#ef4444">ERROR: Set your Grok API key first.</span>')
            return
        box = self._t_box.text().strip(); ip = self._t_ip.text().strip()
        if not box or not ip:
            self._t_log.append('<span style="color:#ef4444">ERROR: Box name and IP required.</span>')
            return
        self._flags = []; self._flag_lbl.setText("Hunting…")
        self._t_launch.setEnabled(False); self._t_hint_btn.setEnabled(True)
        self._t_log.clear()
        self._runner = TrainingRunner(
            api_key=self._api_key, box_name=box, target_ip=ip,
            difficulty=self._t_diff.currentData(),
            category=self._t_cat.currentData(),
            hint=self._t_hint.text().strip(),
        )
        self._runner.log_signal.connect(self._t_on_log)
        self._runner.finding_signal.connect(self._t_on_finding)
        self._runner.flag_signal.connect(self._t_on_flag)
        self._runner.complete_signal.connect(self._t_on_complete)
        self._runner.start()

    def _give_hint(self):
        hint,ok = QInputDialog.getText(self,"Give Hint","Enter hint for the swarm (saved to memory):")
        if ok and hint.strip():
            if self._runner and self._runner._trainer:
                self._runner._trainer.give_hint(hint.strip())
            ts = datetime.now().strftime("%H:%M:%S")
            self._t_log.append(f'<span style="color:#f59e0b">[{ts}] [HINT] {hint}</span>')

    def _t_on_log(self, msg, level):
        cols = {"info":C["text2"],"success":C["green"],"warning":C["amber"],"error":C["red"]}
        c = cols.get(level, C["text2"])
        ts = datetime.now().strftime("%H:%M:%S")
        safe = msg.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
        self._t_log.append(f'<span style="color:{C["text3"]}">[{ts}]</span> <span style="color:{c}">{safe}</span>')
        self._t_log.verticalScrollBar().setValue(self._t_log.verticalScrollBar().maximum())

    def _t_on_finding(self, f):
        sev = f.get("severity","info")
        c = {"critical":C["red"],"high":C["red"],"medium":C["amber"],"low":C["green"]}.get(sev,C["text3"])
        ts = datetime.now().strftime("%H:%M:%S")
        self._t_log.append(f'<span style="color:{C["text3"]}">[{ts}]</span> <span style="color:{c}">[{sev.upper():<8}] {f.get("title","")[:80]}</span>')

    def _t_on_flag(self, flag):
        self._flags.append(flag)
        self._flag_lbl.setText("\n".join(self._flags))
        ts = datetime.now().strftime("%H:%M:%S")
        self._t_log.append(f'<span style="color:{C["green"]};font-weight:bold">[{ts}] 🚩 FLAG: {flag}</span>')

    def _t_on_complete(self, result):
        self._t_launch.setEnabled(True); self._t_hint_btn.setEnabled(False)
        oc = result.get("outcome","unknown"); dur = result.get("duration_secs",0)
        c  = C["green"] if oc=="success" else C["amber"]
        ts = datetime.now().strftime("%H:%M:%S")
        self._t_log.append(f'<span style="color:{c};font-weight:bold">[{ts}] Complete — {oc.upper()}  flags:{len(self._flags)}  {dur//60}m{dur%60}s</span>')
        self._refresh_stats(); self._refresh_episodes(); self._refresh_patterns()
