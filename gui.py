"""
gui.py
Desktop interface for SkyAV — dark theme, no command line needed.
Run: python gui.py  (or: python main.py --gui)
"""


import os
import threading
import time
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

import scanner
import quarantine
import monitor
import logger
import virustotal
import registry_guard
import tray_icon
import process_monitor
import alerts
import whitelist
import ai_explain
import updater
import startup
import honeypot
import usb_guard
import network_monitor
import threat_hunter
import self_protect
import browser_guard
import startup_manager
import task_scanner
import restore_point
import download_guard
import cmd_monitor
import cmd_analyzer

# ---------- Color palette ----------
BG         = "#0d0e17"
BG_SIDEBAR = "#0a0b12"
BG_PANEL   = "#171926"
BG_CARD    = "#1b1e2e"
BG_LOG     = "#0a0b12"
ACCENT     = "#7c5cff"
ACCENT2    = "#4f8cff"
ACCENT_HOVER = "#9a80ff"
NAV_SELECTED = "#1f2140"
GREEN  = "#2ecc8f"
RED    = "#ff5d6c"
ORANGE = "#ffb454"
TEXT     = "#eceefb"
TEXT_DIM = "#888dab"
BORDER   = "#262a40"


def _lerp_color(c1, c2, t):
    c1 = c1.lstrip("#"); c2 = c2.lstrip("#")
    r1,g1,b1 = int(c1[0:2],16),int(c1[2:4],16),int(c1[4:6],16)
    r2,g2,b2 = int(c2[0:2],16),int(c2[2:4],16),int(c2[4:6],16)
    r=int(r1+(r2-r1)*t); g=int(g1+(g2-g1)*t); b=int(b1+(b2-b1)*t)
    return f"#{r:02x}{g:02x}{b:02x}"


class RoundButton(tk.Button):
    def __init__(self, master, text, command, bg=ACCENT, fg="#0d0e14", **kwargs):
        super().__init__(master, text=text, command=command,
            bg=bg, fg=fg, activebackground=_lerp_color(bg,"#ffffff",0.18),
            activeforeground=fg, font=("Segoe UI",10,"bold"),
            relief="flat", bd=0, padx=14, pady=9, cursor="hand2", **kwargs)
        self._bg = bg
        self.bind("<Enter>", lambda e: self.config(bg=_lerp_color(self._bg,"#ffffff",0.18)))
        self.bind("<Leave>", lambda e: self.config(bg=self._bg))

    def set_bg(self, bg):
        self._bg = bg
        self.config(bg=bg, activebackground=_lerp_color(bg,"#ffffff",0.18))


class NavButton(tk.Frame):
    def __init__(self, master, icon, label, command, **kwargs):
        super().__init__(master, bg=BG_SIDEBAR, **kwargs)
        self.command = command
        self.selected = False
        self.bar = tk.Frame(self, bg=BG_SIDEBAR, width=3)
        self.bar.pack(side="left", fill="y")
        inner = tk.Frame(self, bg=BG_SIDEBAR, cursor="hand2")
        inner.pack(side="left", fill="both", expand=True, padx=(12,0), pady=10)
        self.inner = inner
        self.icon_lbl = tk.Label(inner, text=icon, font=("Segoe UI",13), bg=BG_SIDEBAR, fg=TEXT_DIM)
        self.icon_lbl.pack(side="left")
        self.text_lbl = tk.Label(inner, text="  "+label, font=("Segoe UI",11), bg=BG_SIDEBAR, fg=TEXT_DIM)
        self.text_lbl.pack(side="left")
        for w in (self, inner, self.icon_lbl, self.text_lbl):
            w.bind("<Button-1>", lambda e: self.command())
            w.bind("<Enter>",    self._on_enter)
            w.bind("<Leave>",    self._on_leave)

    def _on_enter(self, e):
        if not self.selected:
            for w in (self, self.inner, self.icon_lbl, self.text_lbl):
                w.config(bg="#12141f")

    def _on_leave(self, e):
        if not self.selected:
            for w in (self, self.inner, self.icon_lbl, self.text_lbl):
                w.config(bg=BG_SIDEBAR)

    def set_selected(self, sel):
        self.selected = sel
        bg  = NAV_SELECTED if sel else BG_SIDEBAR
        bar = ACCENT       if sel else BG_SIDEBAR
        fg  = TEXT         if sel else TEXT_DIM
        for w in (self, self.inner, self.icon_lbl, self.text_lbl):
            w.config(bg=bg)
        self.icon_lbl.config(fg=fg)
        self.text_lbl.config(fg=fg)
        self.bar.config(bg=bar)


class SkyAVApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SkyAV — Custom Antivirus")
        self.root.geometry("1060x700")
        self.root.configure(bg=BG)
        self.root.minsize(900, 580)

        icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets", "icon.ico")
        if os.path.exists(icon_path):
            try: self.root.iconbitmap(icon_path)
            except Exception: pass

        self.monitor_thread     = None
        self.monitor_stop_flag  = threading.Event()
        self.guard_thread       = None
        self.guard_stop_flag    = threading.Event()
        self._last_summary      = None
        self.tray               = None
        self._scan_busy         = False
        self._honeypot_observer = None
        self._usb_thread        = None
        self._usb_stop          = threading.Event()
        self._network_thread    = None
        self._network_stop      = threading.Event()
        self._self_protect_observer  = None
        self._download_guard_observer= None
        self._cmd_monitor            = None
        self._pages      = {}
        self._nav_btns   = {}
        self._pulse_job  = None
        self._pulse_step = 0

        self._build_ui()
        self._setup_tray()
        self.root.protocol("WM_DELETE_WINDOW", self._minimize_to_tray)

    # ──────────────────────────────────────────
    #  UI LAYOUT
    # ──────────────────────────────────────────
    def _build_ui(self):
        main = tk.Frame(self.root, bg=BG)
        main.pack(fill="both", expand=True)

        # ── Sidebar ───────────────────────────
        sb = tk.Frame(main, bg=BG_SIDEBAR, width=220)
        sb.pack(side="left", fill="y")
        sb.pack_propagate(False)

        # Gradient banner
        banner = tk.Canvas(sb, width=220, height=90, bg=BG_SIDEBAR, highlightthickness=0)
        banner.pack(fill="x")
        steps = 45
        for i in range(steps):
            t = i/steps
            c = _lerp_color(ACCENT, ACCENT2, t)
            banner.create_rectangle(0, i*(90/steps), 220, (i+1)*(90/steps)+1, fill=c, outline=c)
        banner.create_text(20, 36, text="🛡", font=("Segoe UI",22,"bold"), fill="#fff", anchor="w")
        banner.create_text(58, 28, text="SkyAV",         font=("Segoe UI",15,"bold"), fill="#fff",   anchor="w")
        banner.create_text(58, 50, text="Custom Antivirus", font=("Segoe UI",8),      fill="#e8e4ff", anchor="w")

        tk.Frame(sb, bg=BORDER, height=1).pack(fill="x")

        nav_area = tk.Frame(sb, bg=BG_SIDEBAR)
        nav_area.pack(fill="x", pady=(10,0))
        for key, icon, label in [
            ("dashboard",  "🏠", "Dashboard"),
            ("scan",       "🔍", "Scan"),
            ("protection", "🛡", "Protection"),
            ("tools",      "🧰", "Tools"),
        ]:
            btn = NavButton(nav_area, icon, label, lambda k=key: self._show_page(k))
            btn.pack(fill="x")
            self._nav_btns[key] = btn

        # Status pill at bottom of sidebar
        sp = tk.Frame(sb, bg=BG_SIDEBAR)
        sp.pack(side="bottom", fill="x", padx=16, pady=16)
        pill = tk.Frame(sp, bg=BG_CARD)
        pill.pack(fill="x")
        dr = tk.Frame(pill, bg=BG_CARD)
        dr.pack(fill="x", padx=12, pady=10)
        self.status_dot   = tk.Label(dr, text="●", font=("Segoe UI",12), bg=BG_CARD, fg=TEXT_DIM)
        self.status_dot.pack(side="left")
        self.status_label = tk.Label(dr, text=" Idle", font=("Segoe UI",9),  bg=BG_CARD, fg=TEXT_DIM)
        self.status_label.pack(side="left")

        # ── Right side ────────────────────────
        right = tk.Frame(main, bg=BG)
        right.pack(side="left", fill="both", expand=True)

        page_host = tk.Frame(right, bg=BG)
        page_host.pack(fill="both", expand=True, padx=28, pady=(22,10))

        self._pages["dashboard"]  = self._build_dashboard(page_host)
        self._pages["scan"]       = self._build_scan(page_host)
        self._pages["protection"] = self._build_protection(page_host)
        self._pages["tools"]      = self._build_tools(page_host)
        for p in self._pages.values():
            p.place(relx=0, rely=0, relwidth=1, relheight=1)

        # ── Persistent log ─────────────────────
        tk.Frame(right, bg=BORDER, height=1).pack(fill="x", padx=28)
        lr = tk.Frame(right, bg=BG, padx=28)
        lr.pack(fill="x", pady=(8,4))
        tk.Label(lr, text="ACTIVITY LOG", font=("Segoe UI",9,"bold"), bg=BG, fg=TEXT_DIM).pack(side="left")

        lf = tk.Frame(right, bg=BG, padx=28)
        lf.pack(fill="both", expand=False, pady=(0,18))
        lf.configure(height=200)
        lf.pack_propagate(False)

        lc = tk.Frame(lf, bg=BORDER, bd=1)
        lc.pack(fill="both", expand=True)
        self.log_text = tk.Text(lc, wrap="word", font=("Cascadia Code",9),
                                bg=BG_LOG, fg=TEXT, insertbackground=TEXT,
                                relief="flat", padx=12, pady=10, bd=0)
        self.log_text.pack(side="left", fill="both", expand=True)
        sb2 = ttk.Scrollbar(lc, command=self.log_text.yview)
        sb2.pack(side="right", fill="y")
        self.log_text.config(yscrollcommand=sb2.set)
        self.log_text.tag_config("clean",     foreground=GREEN)
        self.log_text.tag_config("infected",  foreground=RED)
        self.log_text.tag_config("suspicious",foreground=ORANGE)
        self.log_text.tag_config("dim",       foreground=TEXT_DIM)
        self.log_text.tag_config("heading",   foreground=ACCENT, font=("Cascadia Code",9,"bold"))

        self._log("SkyAV ready. Choose a scan type above.", "dim")
        self._show_page("dashboard")

    # ── Page builders ─────────────────────────
    def _ptitle(self, parent, title, subtitle=None):
        tk.Label(parent, text=title, font=("Segoe UI",18,"bold"), bg=BG, fg=TEXT).pack(anchor="w")
        if subtitle:
            tk.Label(parent, text=subtitle, font=("Segoe UI",9), bg=BG, fg=TEXT_DIM).pack(anchor="w", pady=(2,0))

    def _stat_card(self, parent, label, value, color):
        f = tk.Frame(parent, bg=BG_CARD, padx=20, pady=16)
        vl = tk.Label(f, text=value, font=("Segoe UI",22,"bold"), bg=BG_CARD, fg=color)
        vl.pack(anchor="w")
        tk.Label(f, text=label, font=("Segoe UI",9), bg=BG_CARD, fg=TEXT_DIM).pack(anchor="w")
        return {"frame": f, "vl": vl}

    def _build_dashboard(self, host):
        p = tk.Frame(host, bg=BG)
        self._ptitle(p, "Dashboard", "Protection status at a glance.")
        cards = tk.Frame(p, bg=BG)
        cards.pack(fill="x", pady=(20,0))
        self._sc = self._stat_card(cards, "Protection Score", "—",   ACCENT)
        self._sc["frame"].pack(side="left", padx=(0,12))
        self._tc = self._stat_card(cards, "Threats Blocked",  "0",   GREEN)
        self._tc["frame"].pack(side="left", padx=12)
        self._gc = self._stat_card(cards, "Signature DB",     "—",   ACCENT2)
        self._gc["frame"].pack(side="left", padx=12)

        tk.Label(p, text="QUICK ACTIONS", font=("Segoe UI",9,"bold"), bg=BG, fg=TEXT_DIM).pack(anchor="w", pady=(26,8))
        qr = tk.Frame(p, bg=BG)
        qr.pack(fill="x")
        RoundButton(qr, "⚡ Quick Scan",          self.run_quick_scan,         bg=ACCENT,  fg="#fff").pack(side="left", padx=(0,8))
        RoundButton(qr, "🤖 AI Threat Hunt",       self.open_threat_hunter,     bg=ACCENT2, fg="#fff").pack(side="left", padx=8)
        RoundButton(qr, "🛡 Enable All Protection", self._enable_all_protection, bg=GREEN,   fg="#0d0e14").pack(side="left", padx=8)
        return p

    def _build_scan(self, host):
        p = tk.Frame(host, bg=BG)
        self._ptitle(p, "Scan", "Check files and running processes for threats.")
        sr = tk.Frame(p, bg=BG)
        sr.pack(fill="x", pady=(20,8))
        self.quick_scan_btn   = RoundButton(sr, "⚡ Quick Scan",      self.run_quick_scan,   bg=ACCENT,  fg="#fff")
        self.quick_scan_btn.pack(side="left", padx=(0,8))
        self.full_scan_btn    = RoundButton(sr, "🔍 Full Scan",        self.run_full_scan,    bg=ACCENT2, fg="#fff")
        self.full_scan_btn.pack(side="left", padx=8)
        self.custom_scan_btn  = RoundButton(sr, "📁 Custom Scan…",    self.run_custom_scan,  bg=ACCENT2, fg="#fff")
        self.custom_scan_btn.pack(side="left", padx=8)
        self.process_scan_btn = RoundButton(sr, "⚙ Scan Processes",   self.run_process_scan, bg=ACCENT2, fg="#fff")
        self.process_scan_btn.pack(side="left", padx=8)

        self.auto_quarantine_var = tk.BooleanVar(value=False)
        ar = tk.Frame(p, bg=BG); ar.pack(fill="x", pady=(4,0))
        tk.Checkbutton(ar, text="Auto-quarantine threats found during scans",
                       variable=self.auto_quarantine_var,
                       bg=BG, fg=TEXT_DIM, selectcolor=BG_PANEL,
                       activebackground=BG, activeforeground=TEXT,
                       font=("Segoe UI",9), cursor="hand2", bd=0,
                       highlightthickness=0).pack(side="left")
        return p

    def _build_protection(self, host):
        p = tk.Frame(host, bg=BG)
        self._ptitle(p, "Protection", "Always-on guards watching your system in real time.")
        r1 = tk.Frame(p, bg=BG); r1.pack(fill="x", pady=(20,8))
        self.protect_btn  = RoundButton(r1, "▶ Real-Time Protection", self.toggle_protection, bg=GREEN, fg="#0d0e14")
        self.protect_btn.pack(side="left", padx=(0,8))
        self.guard_btn    = RoundButton(r1, "▶ Registry Guard",       self.toggle_guard,       bg=GREEN, fg="#0d0e14")
        self.guard_btn.pack(side="left", padx=8)

        r2 = tk.Frame(p, bg=BG); r2.pack(fill="x", pady=8)
        self.honeypot_btn = RoundButton(r2, "🍯 Honeypot",        self.toggle_honeypot,       bg=GREEN, fg="#0d0e14")
        self.honeypot_btn.pack(side="left", padx=(0,8))
        self.usb_btn      = RoundButton(r2, "💾 USB Auto-Scan",   self.toggle_usb_guard,      bg=GREEN, fg="#0d0e14")
        self.usb_btn.pack(side="left", padx=8)
        self.net_btn      = RoundButton(r2, "🌐 Network Monitor", self.toggle_network_monitor, bg=GREEN, fg="#0d0e14")
        self.net_btn.pack(side="left", padx=8)

        r3 = tk.Frame(p, bg=BG); r3.pack(fill="x", pady=8)
        self.selfp_btn    = RoundButton(r3, "🔒 Self-Protect",   self.toggle_self_protect,   bg=GREEN, fg="#0d0e14")
        self.selfp_btn.pack(side="left", padx=(0,8))
        self.dlguard_btn  = RoundButton(r3, "⬇ Download Guard",  self.toggle_download_guard, bg=GREEN, fg="#0d0e14")
        self.dlguard_btn.pack(side="left", padx=8)

        r4 = tk.Frame(p, bg=BG); r4.pack(fill="x", pady=8)
        self.cmdmon_btn = RoundButton(r4, "💻 CMD Monitor", self.toggle_cmd_monitor, bg=GREEN, fg="#0d0e14")
        self.cmdmon_btn.pack(side="left", padx=(0,8))
        return p

    def _build_tools(self, host):
        p = tk.Frame(host, bg=BG)
        self._ptitle(p, "Tools", "Extra utilities for deeper inspection and cleanup.")
        r1 = tk.Frame(p, bg=BG); r1.pack(fill="x", pady=(20,8))
        RoundButton(r1, "🗂 Quarantine",    self.view_quarantine,    bg=BG_PANEL, fg=TEXT).pack(side="left", padx=(0,8))
        RoundButton(r1, "☁ Check VT",      self.run_vt_check,       bg=BG_PANEL, fg=TEXT).pack(side="left", padx=8)
        RoundButton(r1, "🔑 Set VT Key",   self.set_vt_key,         bg=BG_PANEL, fg=TEXT).pack(side="left", padx=8)
        RoundButton(r1, "📜 History",       self.view_history,       bg=BG_PANEL, fg=TEXT).pack(side="left", padx=8)
        RoundButton(r1, "🤖 AI Hunt",       self.open_threat_hunter, bg=ACCENT,   fg="#fff").pack(side="left", padx=8)

        r2 = tk.Frame(p, bg=BG); r2.pack(fill="x", pady=8)
        RoundButton(r2, "🏳 Review Flagged", self.review_flagged, bg=BG_PANEL, fg=TEXT).pack(side="left", padx=(0,8))
        RoundButton(r2, "📱 Set Telegram",   self.set_telegram,   bg=BG_PANEL, fg=TEXT).pack(side="left", padx=8)
        RoundButton(r2, "🎮 Set Discord",    self.set_discord,    bg=BG_PANEL, fg=TEXT).pack(side="left", padx=8)
        RoundButton(r2, "📧 Set Email",      self.set_email,      bg=BG_PANEL, fg=TEXT).pack(side="left", padx=8)
        RoundButton(r2, "⚙ Settings",       self.open_settings,  bg=BG_PANEL, fg=TEXT).pack(side="left", padx=8)

        r3 = tk.Frame(p, bg=BG); r3.pack(fill="x", pady=8)
        RoundButton(r3, "🌐 Browser Guard",   self.run_browser_guard,    bg=BG_PANEL, fg=TEXT).pack(side="left", padx=(0,8))
        RoundButton(r3, "🚀 Startup Manager", self.open_startup_manager, bg=BG_PANEL, fg=TEXT).pack(side="left", padx=8)
        RoundButton(r3, "📅 Task Scanner",    self.open_task_scanner,    bg=BG_PANEL, fg=TEXT).pack(side="left", padx=8)
        RoundButton(r3, "💾 Restore Point",   self.create_restore_point, bg=BG_PANEL, fg=TEXT).pack(side="left", padx=8)

        r4 = tk.Frame(p, bg=BG); r4.pack(fill="x", pady=8)
        RoundButton(r4, "🔍 Analyze Command", self.open_cmd_analyzer, bg=ACCENT, fg="#fff").pack(side="left", padx=(0,8))
        return p

    # ── Navigation ────────────────────────────
    def _show_page(self, key):
        for k, b in self._nav_btns.items():
            b.set_selected(k == key)
        self._pages[key].tkraise()
        if key == "dashboard":
            self._refresh_dashboard()

    def _refresh_dashboard(self):
        btns = [self.protect_btn, self.guard_btn, self.honeypot_btn,
                self.usb_btn, self.net_btn, self.selfp_btn, self.dlguard_btn,
                self.cmdmon_btn]
        active = sum(1 for b in btns if getattr(b, "_bg", GREEN) == RED)
        total  = len(btns)
        self._sc["vl"].config(text=f"{active}/{total}",
                               fg=GREEN if active==total else (ORANGE if active>0 else RED))
        try:
            info = updater.get_last_update_info()
            self._gc["vl"].config(text=str(info.get("total_signatures", 0)))
        except Exception:
            pass

    def _enable_all_protection(self):
        pairs = [(self.protect_btn, self.toggle_protection),
                 (self.guard_btn,   self.toggle_guard),
                 (self.honeypot_btn,self.toggle_honeypot),
                 (self.usb_btn,     self.toggle_usb_guard),
                 (self.net_btn,     self.toggle_network_monitor),
                 (self.selfp_btn,   self.toggle_self_protect),
                 (self.dlguard_btn, self.toggle_download_guard),
                 (self.cmdmon_btn,  self.toggle_cmd_monitor)]
        for btn, fn in pairs:
            if getattr(btn, "_bg", GREEN) != RED:
                fn()
        self._refresh_dashboard()

    # ── Helpers ───────────────────────────────
    def _log(self, msg, tag=None):
        self.log_text.insert("end", msg + "\n", tag)
        self.log_text.see("end")

    def _set_status(self, text, color=TEXT_DIM):
        self.status_label.config(text=f" {text}", fg=color)
        if color == ORANGE:
            self._start_pulse()
        else:
            self._stop_pulse()
            self.status_dot.config(fg=color)

    def _start_pulse(self):
        if self._pulse_job:
            return
        def step():
            self._pulse_step ^= 1
            self.status_dot.config(fg=ORANGE if self._pulse_step else _lerp_color(ORANGE,BG_CARD,0.5))
            self._pulse_job = self.root.after(500, step)
        step()

    def _stop_pulse(self):
        if self._pulse_job:
            self.root.after_cancel(self._pulse_job)
            self._pulse_job = None

        self.status_dot.config(fg=color)
        self.status_label.config(text=f" {text}", fg=color)

    def _make_scrollable(self, parent):
        """Creates a canvas+scrollframe with working mousewheel support.
        Returns (canvas, scroll_frame)."""
        canvas = tk.Canvas(parent, bg=BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview)
        scroll_frame = tk.Frame(canvas, bg=BG)

        scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        def _on_mousewheel(event):
            canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

        # Windows: bind to the Toplevel window so scroll works regardless
        # of which child widget the mouse is hovering over
        top = parent.winfo_toplevel()
        top.bind("<MouseWheel>", _on_mousewheel, add="+")

        def _bind_all(widget):
            widget.bind("<MouseWheel>", _on_mousewheel, add="+")
            for child in widget.winfo_children():
                _bind_all(child)

        canvas.bind("<MouseWheel>", _on_mousewheel, add="+")
        scroll_frame.bind("<MouseWheel>", _on_mousewheel, add="+")
        scroll_frame._bind_children = _bind_all
        return canvas, scroll_frame

    @staticmethod
    def _explain_threat(item: dict) -> str:
        """Returns a plain-English explanation of why a file was flagged and what to do."""
        detail = item.get("detail", "").lower()
        status = item.get("status", "")
        name = os.path.basename(item.get("path", ""))
        lines = []

        if "known malware" in detail:
            lines.append(f"⛔ '{name}' matches a confirmed malware signature in the database.")
            lines.append("   What to do: Quarantine immediately and do NOT open this file.")
        elif "double file extension" in detail:
            lines.append(f"⚠ '{name}' is using a disguise trick — it pretends to be a document")
            lines.append("   but is actually an executable. Real files like 'photo.jpg' don't")
            lines.append("   need a second '.exe' extension. This is a common malware trick.")
            lines.append("   What to do: Delete this file unless you are 100% sure of its source.")
        elif "high entropy" in detail:
            lines.append(f"⚠ '{name}' appears to be packed or encrypted.")
            lines.append("   Legitimate software can also be packed (installers, game launchers),")
            lines.append("   so this alone doesn't confirm malware. Check with VirusTotal first.")
            lines.append("   What to do: Use 'Check VT' to verify before deciding.")
        elif "yara rule matched" in detail and "powershell" in detail:
            lines.append(f"⚠ '{name}' contains PowerShell code that downloads and runs remote content.")
            lines.append("   Legitimate scripts rarely do this silently. Malware often uses this")
            lines.append("   pattern to pull and execute a payload from the internet.")
            lines.append("   What to do: Do NOT run this file. Check its source carefully.")
        elif "yara rule matched" in detail and "injection" in detail:
            lines.append(f"⚠ '{name}' contains process-injection code patterns.")
            lines.append("   This means the file can inject code into other running programs,")
            lines.append("   which is a core technique used by RATs and spyware.")
            lines.append("   What to do: Use 'Check VT' to verify. Quarantine if uncertain.")
        elif "rat-like capabilities" in detail or "classic rat" in detail:
            lines.append(f"⚠ '{name}' imports a combination of Windows APIs that together suggest")
            lines.append("   remote-control or spyware capabilities (keylogging, screen capture,")
            lines.append("   network access, process injection).")
            lines.append("   NOTE: Some legitimate tools (overlays, remote desktop apps) also")
            lines.append("   use these APIs. Check the file's source before acting.")
            lines.append("   What to do: If unknown, quarantine and check with VirusTotal.")
        elif "suspicious code pattern" in detail:
            lines.append(f"⚠ '{name}' contains strings commonly found in malicious scripts")
            lines.append("   (shell commands, registry writes, download triggers).")
            lines.append("   If this is a script you wrote or downloaded intentionally, it may")
            lines.append("   be a false positive. Otherwise treat it with caution.")
            lines.append("   What to do: Check the file's origin. Use 'Check VT' if unsure.")
        elif "trusted digital signature" in detail:
            lines.append(f"✅ '{name}' is digitally signed by a verified publisher.")
            lines.append("   This means Windows itself has verified the file's authenticity.")
            lines.append("   What to do: Safe — mark as whitelisted.")
        elif "whitelisted" in detail:
            lines.append(f"✅ '{name}' was previously confirmed safe by you.")
        else:
            lines.append(f"⚠ '{name}' was flagged as {status}.")
            lines.append(f"   Reason: {item.get('detail', 'unknown')}")
            lines.append("   What to do: Use 'Check VT' button to verify with VirusTotal.")

        return "\n".join(lines)

    def _set_scan_buttons_enabled(self, enabled: bool):
        state = "normal" if enabled else "disabled"
        for btn in (self.quick_scan_btn, self.full_scan_btn, self.custom_scan_btn, self.process_scan_btn):
            btn.config(state=state)

    def _run_scan_thread(self, scan_fn, scan_name, *args):
        if self._scan_busy:
            messagebox.showinfo("Scan in progress", "A scan is already running — please wait for it to finish.")
            return
        self._scan_busy = True
        self._set_scan_buttons_enabled(False)
        self._set_status(f"Running {scan_name}...", ORANGE)
        self._log(f"\n=== {scan_name} started ===", "heading")

        def worker():
            start = time.time()
            summary = scan_fn(*args, progress_callback=None)
            elapsed = time.time() - start
            logger.log_scan(scan_name, summary, elapsed)
            self._last_summary = summary
            self.root.after(0, lambda: self._show_summary(summary, elapsed, scan_name))

        threading.Thread(target=worker, daemon=True).start()

    def _show_summary(self, summary, elapsed, scan_name):
        self._scan_busy = False
        self._set_scan_buttons_enabled(True)
        self._set_status("Idle", TEXT_DIM)
        self._log(f"=== {scan_name} complete in {elapsed:.1f}s ===", "heading")
        self._log(f"Scanned: {summary['scanned']}  Infected: {summary['infected']}  "
                   f"Suspicious: {summary['suspicious']}  Skipped: {summary['skipped']}", "dim")

        for item in summary["flagged"]:
            tag = "infected" if item["status"] == "infected" else "suspicious"
            self._log(f"\n  [{item['status'].upper()}] {item['path']}", tag)
            self._log(f"  Reason: {item['detail']}", "dim")
            self._log("  ──────────────────────────────────", "dim")
            self._log("  🤖 Getting AI explanation...", "dim")

            def fetch_and_show(i=item):
                explanation = ai_explain.explain_threat(
                    i["path"], i["status"], i["detail"]
                )
                self.root.after(0, lambda exp=explanation: (
                    self._log(f"\n{exp}\n", "dim")
                ))

            threading.Thread(target=fetch_and_show, daemon=True).start()

        if not summary["flagged"]:
            self._log("  No threats found. ✅", "clean")

    # ---------- BUTTON ACTIONS ----------
    def run_quick_scan(self):
        self._run_scan_thread(scanner.quick_scan, "Quick Scan", self.auto_quarantine_var.get())

    def run_full_scan(self):
        if not messagebox.askyesno("Full Scan", "Full scan checks the entire drive and can take several minutes. Continue?"):
            return
        self._run_scan_thread(scanner.full_scan, "Full Scan", self.auto_quarantine_var.get())

    def run_custom_scan(self):
        folder = filedialog.askdirectory(title="Select folder to scan")
        if folder:
            self._run_scan_thread(scanner.custom_scan, "Custom Scan", folder, self.auto_quarantine_var.get())

    def run_process_scan(self):
        if self._scan_busy:
            messagebox.showinfo("Scan in progress", "A scan is already running — please wait for it to finish.")
            return
        self._scan_busy = True
        self._set_scan_buttons_enabled(False)
        self._set_status("Scanning processes...", ORANGE)
        self._log("\n=== Process Scan started ===", "heading")

        def worker():
            flagged = process_monitor.scan_running_processes()
            self.root.after(0, lambda: self._show_process_results(flagged))

        threading.Thread(target=worker, daemon=True).start()

    def _show_process_results(self, flagged):
        self._scan_busy = False
        self._set_scan_buttons_enabled(True)
        self._set_status("Idle", TEXT_DIM)
        self._log(f"=== Process Scan complete ===", "heading")

        if not flagged:
            self._log("  No suspicious running processes found. ✅", "clean")
            return

        self._log(f"  {len(flagged)} suspicious process(es) found — review below.", "suspicious")

        # Show all results in one window instead of one popup per process
        win = tk.Toplevel(self.root)
        win.title("Suspicious Processes — Review")
        win.geometry("700x480")
        win.configure(bg=BG)

        tk.Label(win, text="Suspicious Processes", font=("Segoe UI", 13, "bold"),
                  bg=BG, fg=TEXT, padx=15, pady=12).pack(anchor="w")
        tk.Label(win, text="Review each process below and decide what to do.",
                  font=("Segoe UI", 9), bg=BG, fg=TEXT_DIM, padx=15).pack(anchor="w", pady=(0, 8))

        canvas_frame = tk.Frame(win, bg=BG)
        canvas_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        canvas, scroll_frame = self._make_scrollable(canvas_frame)

        for p in flagged:
            row = tk.Frame(scroll_frame, bg=BG_PANEL, padx=10, pady=8)
            row.pack(fill="x", pady=4)
            if hasattr(scroll_frame, '_bind_children'):
                scroll_frame._bind_children(row)

            info_frame = tk.Frame(row, bg=BG_PANEL)
            info_frame.pack(side="left", fill="x", expand=True)

            tk.Label(info_frame,
                      text=f"[PID {p['pid']}] {p['name']}  (score: {p['score']})",
                      font=("Segoe UI", 10, "bold"), bg=BG_PANEL, fg=ORANGE, anchor="w").pack(fill="x")
            tk.Label(info_frame, text=p["path"], font=("Segoe UI", 8),
                      bg=BG_PANEL, fg=TEXT_DIM, anchor="w", wraplength=420, justify="left").pack(fill="x")
            for reason in p["reasons"]:
                tk.Label(info_frame, text=f"  → {reason}", font=("Segoe UI", 8),
                          bg=BG_PANEL, fg=TEXT_DIM, anchor="w", wraplength=420, justify="left").pack(fill="x")

            # AI explanation label — updated once API call returns
            explain_var = tk.StringVar(value="🤖 Getting AI explanation...")
            tk.Label(info_frame, textvariable=explain_var, font=("Segoe UI", 8),
                      bg=BG_PANEL, fg=ACCENT, anchor="w", wraplength=420,
                      justify="left").pack(fill="x", pady=(4, 0))

            def fetch_explanation(proc=p, var=explain_var):
                detail = "; ".join(proc["reasons"])
                exp = ai_explain.explain_threat(proc["path"], "suspicious", detail)
                self.root.after(0, lambda e=exp: var.set(e))

            threading.Thread(target=fetch_explanation, daemon=True).start()

            btn_frame = tk.Frame(row, bg=BG_PANEL)
            btn_frame.pack(side="right", padx=(8, 0))

            def make_terminate(proc=p, row=row):
                def action():
                    success = process_monitor.kill_process(proc["pid"])
                    self._log(
                        f"  {'Terminated' if success else 'FAILED to terminate'} PID {proc['pid']} ({proc['name']})",
                        "clean" if success else "infected")
                    row.destroy()
                return action

            def make_safe(proc=p, row=row):
                def action():
                    if proc["path"] and proc["path"] != "(unknown)":
                        whitelist.add_to_whitelist(proc["path"], "Manually marked safe (process scan)")
                        self._log(f"  Marked as safe: {proc['name']}", "clean")
                    row.destroy()
                return action

            RoundButton(btn_frame, "⚠ Terminate", make_terminate(), bg=RED, fg="#ffffff").pack(pady=(0, 4))
            RoundButton(btn_frame, "✓ Safe", make_safe(), bg=GREEN, fg="#0d0e14").pack()



    def toggle_protection(self):
        if self.monitor_thread and self.monitor_thread.is_alive():
            self.monitor_stop_flag.set()
            self.protect_btn.config(text="▶ Start Real-Time Protection", bg=GREEN)
            self.protect_btn._bg = GREEN
            self._log("Real-time protection stopping...", "dim")
        else:
            self.monitor_stop_flag.clear()

            def on_detect(result):
                logger.log_realtime_detection(result)
                tag = "infected" if result["status"] == "infected" else "suspicious"
                self.root.after(0, lambda: self._log(
                    f"🚨 [{result['status'].upper()}] {result['path']} -> {result['detail']}", tag))

            def worker():
                paths = [p for p in monitor.get_watch_paths() if os.path.exists(p)]
                handler = monitor.ThreatHandler(auto_quarantine=True, on_detect=on_detect)
                from watchdog.observers import Observer
                observer = Observer()
                for p in paths:
                    observer.schedule(handler, p, recursive=True)
                observer.start()
                while not self.monitor_stop_flag.is_set():
                    time.sleep(0.5)
                observer.stop()
                observer.join()

            self.monitor_thread = threading.Thread(target=worker, daemon=True)
            self.monitor_thread.start()
            self.protect_btn.config(text="■ Stop Real-Time Protection", bg=RED)
            self.protect_btn._bg = RED
            self._log("Real-time protection started — watching Downloads, Temp, Startup, Desktop.", "clean")

    def toggle_guard(self):
        if self.guard_thread and self.guard_thread.is_alive():
            self.guard_stop_flag.set()
            self.guard_btn.config(text="▶ Start Registry Guard", bg=GREEN)
            self.guard_btn._bg = GREEN
            self._log("Registry guard stopping...", "dim")
        else:
            self.guard_stop_flag.clear()

            def on_alert(alert):
                self.root.after(0, lambda: self._log(f"🚨 {alert['message']}", "infected"))

            def worker():
                if registry_guard.load_baseline() is None:
                    registry_guard.save_baseline()
                while not self.guard_stop_flag.is_set():
                    alerts = registry_guard.check_for_changes()
                    for a in alerts:
                        on_alert(a)
                    if alerts:
                        registry_guard.save_baseline()
                    time.sleep(15)

            self.guard_thread = threading.Thread(target=worker, daemon=True)
            self.guard_thread.start()
            self.guard_btn.config(text="■ Stop Registry Guard", bg=RED)
            self.guard_btn._bg = RED
            self._log("Registry/Startup Guard started — watching for new autorun entries.", "clean")

    def view_quarantine(self):
        items = quarantine.list_quarantine()

        win = tk.Toplevel(self.root)
        win.title("Quarantine Manager")
        win.geometry("640x420")
        win.configure(bg=BG)

        tk.Label(win, text="Quarantined Items", font=("Segoe UI", 13, "bold"),
                  bg=BG, fg=TEXT, padx=15, pady=12).pack(anchor="w")

        if not items:
            tk.Label(win, text="Quarantine is empty.", bg=BG, fg=TEXT_DIM, padx=15).pack(anchor="w")
            return

        canvas_frame = tk.Frame(win, bg=BG)
        canvas_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        canvas, scroll_frame = self._make_scrollable(canvas_frame)

        for qid, info in items.items():
            row = tk.Frame(scroll_frame, bg=BG_PANEL, padx=10, pady=8)
            row.pack(fill="x", pady=4)
            if hasattr(scroll_frame, '_bind_children'):
                scroll_frame._bind_children(row)

            text_frame = tk.Frame(row, bg=BG_PANEL)
            text_frame.pack(side="left", fill="x", expand=True)
            tk.Label(text_frame, text=os.path.basename(info["original_path"]),
                      font=("Segoe UI", 10, "bold"), bg=BG_PANEL, fg=TEXT, anchor="w").pack(fill="x")
            tk.Label(text_frame, text=info["original_path"], font=("Segoe UI", 8),
                      bg=BG_PANEL, fg=TEXT_DIM, anchor="w").pack(fill="x")
            tk.Label(text_frame, text=info["reason"], font=("Segoe UI", 8),
                      bg=BG_PANEL, fg=ORANGE, anchor="w").pack(fill="x")

            btn_frame = tk.Frame(row, bg=BG_PANEL)
            btn_frame.pack(side="right")

            def make_restore(qid=qid, win=win):
                def action():
                    result = quarantine.restore_file(qid)
                    self._log(f"Restored: {result}", "clean")
                    win.destroy()
                    self.view_quarantine()
                return action

            def make_delete(qid=qid, name=os.path.basename(info["original_path"]), win=win):
                def action():
                    if messagebox.askyesno(
                        "Permanently Delete",
                        f"This will PERMANENTLY delete '{name}'.\nThis cannot be undone. Continue?"
                    ):
                        success = quarantine.delete_permanently(qid)
                        self._log(f"{'Permanently deleted' if success else 'Failed to delete'}: {name}",
                                   "clean" if success else "infected")
                        win.destroy()
                        self.view_quarantine()
                return action

            RoundButton(btn_frame, "↩ Restore", make_restore(), bg=GREEN, fg="#0d0e14").pack(side="left", padx=3)
            RoundButton(btn_frame, "🗑 Delete", make_delete(), bg=RED, fg="#ffffff").pack(side="left", padx=3)

    def run_vt_check(self):
        if not self._last_summary or not self._last_summary.get("flagged"):
            messagebox.showinfo("VirusTotal Check", "Run a scan first — there are no flagged files to check yet.")
            return
        self._log("\n=== VirusTotal Cross-Check ===", "heading")

        def worker():
            results = virustotal.check_flagged_files(self._last_summary["flagged"])
            for r in results:
                if r["found"]:
                    tag = "infected" if r["verdict"] == "MALICIOUS" else ("suspicious" if r["verdict"] == "SUSPICIOUS" else "clean")
                    self.root.after(0, lambda r=r, tag=tag: self._log(
                        f"  {r['path']} -> {r['verdict']} ({r['malicious_count']}/{r['total_engines']} engines)\n"
                        f"      {r['permalink']}", tag))
                else:
                    self.root.after(0, lambda r=r: self._log(f"  {r['path']} -> {r['error']}", "dim"))

        threading.Thread(target=worker, daemon=True).start()

    def set_vt_key(self):
        key = simpledialog.askstring("VirusTotal API Key", "Paste your free VirusTotal API key:")
        if key:
            virustotal.save_api_key(key)
            self._log("VirusTotal API key saved.", "clean")

    def set_telegram(self):
        token = simpledialog.askstring("Telegram Bot Token", "Paste your bot token (from @BotFather):")
        if not token:
            return
        chat_id = simpledialog.askstring("Telegram Chat ID", "Paste your chat ID:")
        if not chat_id:
            return
        alerts.save_telegram_config(token, chat_id)
        success = alerts.send_telegram_message("✅ SkyAV is now connected and will send threat alerts here.")
        self._log("Telegram connected — test message sent!" if success else
                   "Telegram config saved, but test message failed — check token/chat ID.",
                   "clean" if success else "infected")

    def set_discord(self):
        webhook_url = simpledialog.askstring("Discord Webhook URL",
                                               "Paste your webhook URL (Channel Settings > Integrations > Webhooks):")
        if not webhook_url:
            return
        alerts.save_discord_webhook(webhook_url)
        success = alerts.send_discord_message("✅ SkyAV is now connected and will send threat alerts here.")
        self._log("Discord connected — test message sent!" if success else
                   "Discord webhook saved, but test message failed — check the URL.",
                   "clean" if success else "infected")

    def set_email(self):
        sender = simpledialog.askstring("Email Alerts — Sender", "Your email address (e.g. Gmail):")
        if not sender:
            return
        app_password = simpledialog.askstring(
            "Email Alerts — App Password",
            "App password (not your normal password — see:\nmyaccount.google.com/apppasswords for Gmail):",
            show="*")
        if not app_password:
            return
        recipient = simpledialog.askstring("Email Alerts — Recipient",
                                             "Where should alerts be sent? (can be same as above):",
                                             initialvalue=sender)
        if not recipient:
            return
        alerts.save_email_config(sender, app_password, recipient)
        error = alerts.send_email_message_debug("SkyAV Connected", "SkyAV is now connected and will send threat alerts here.")
        if error is None:
            self._log("Email connected — test message sent!", "clean")
        else:
            self._log(f"Email config saved, but test failed: {error}", "infected")

    def open_settings(self):
        win = tk.Toplevel(self.root)
        win.title("SkyAV Settings")
        win.geometry("680x480")
        win.minsize(640, 440)
        win.resizable(True, True)
        win.configure(bg=BG)
        win.resizable(False, False)

        tk.Label(win, text="Settings", font=("Segoe UI", 14, "bold"),
                  bg=BG, fg=TEXT, padx=20, pady=15).pack(anchor="w")

        def section(text):
            tk.Label(win, text=text, font=("Segoe UI", 8, "bold"),
                      bg=BG, fg=TEXT_DIM, padx=20).pack(fill="x", pady=(10, 2))
            tk.Frame(win, bg=BORDER, height=1).pack(fill="x", padx=20)

        def row(label, sublabel, btn_text, cmd, btn_color=BG_PANEL):
            f = tk.Frame(win, bg=BG, padx=20, pady=6)
            f.pack(fill="x")
            txt = tk.Frame(f, bg=BG)
            txt.pack(side="left", fill="x", expand=True)
            tk.Label(txt, text=label, font=("Segoe UI", 10, "bold"),
                      bg=BG, fg=TEXT, anchor="w").pack(anchor="w")
            tk.Label(txt, text=sublabel, font=("Segoe UI", 8),
                      bg=BG, fg=TEXT_DIM, anchor="w").pack(anchor="w")
            RoundButton(f, btn_text, cmd, bg=btn_color, fg=TEXT).pack(side="right")

        section("SIGNATURE DATABASE")

        def do_update():
            self._log("\n=== Signature Update started ===", "heading")
            win.destroy()
            def worker():
                result = updater.update_from_malwarebazaar(
                    recent_only=True,
                    progress_callback=lambda m: self.root.after(0, lambda msg=m: self._log(f"  {msg}", "dim"))
                )
                if result["error"]:
                    self.root.after(0, lambda: self._log(f"  Update failed: {result['error']}", "infected"))
                else:
                    self.root.after(0, lambda: self._log(
                        f"  Update complete — {result['added']} new signatures (total: {result['total']})", "clean"))
            threading.Thread(target=worker, daemon=True).start()

        def do_full_update():
            if not messagebox.askyesno("Full DB Download", "This downloads 1M+ malware hashes. Continue?"):
                return
            win.destroy()
            def worker():
                result = updater.update_from_malwarebazaar(
                    recent_only=False,
                    progress_callback=lambda m: self.root.after(0, lambda msg=m: self._log(f"  {msg}", "dim"))
                )
                self.root.after(0, lambda: self._log(
                    f"  Done — {result['added']} new signatures (total: {result['total']})", "clean"
                ))
            threading.Thread(target=worker, daemon=True).start()

        info = updater.get_last_update_info()
        last = info.get("last_update", "Never")
        total = info.get("total_signatures", 0)

        row("Update Signatures Now", f"Last update: {last}  |  Total: {total}", "⬇ Update (1K)", do_update, ACCENT)
        row("Download Full Database", "1M+ confirmed malware hashes from MalwareBazaar", "⬇ Full DB", do_full_update, "#5c6bc0")

        section("SELF-PROTECTION")

        def do_refresh_baseline():
            self_protect.take_integrity_snapshot()
            self._log("Self-Protection baseline refreshed — current files marked as trusted.", "clean")
            win.destroy()

        row("Refresh Baseline",
            "Run this after you edit SkyAV's own code, so Self-Protection doesn't flag your own changes as tampering.",
            "🔄 Refresh", do_refresh_baseline, ACCENT)

        section("WINDOWS STARTUP")
        task_status = startup.get_status()

        def toggle_startup():
            if task_status.get("startup"):
                ok, msg = startup.register_startup(False)
            else:
                ok, msg = startup.register_startup(True)
                startup.register_daily_update(True)
            self._log(f"  {msg}", "clean" if ok else "infected")
            win.destroy()

        def toggle_boot_scan():
            if task_status.get("boot_scan"):
                ok, msg = startup.register_boot_scan(False)
            else:
                ok, msg = startup.register_boot_scan(True)
            self._log(f"  {msg}", "clean" if ok else "infected")
            win.destroy()

        startup_status = "✅ Enabled" if task_status.get("startup") else "❌ Disabled"
        boot_status = "✅ Enabled" if task_status.get("boot_scan") else "❌ Disabled"

        row("Auto-start at Login", f"Launch SkyAV tray at Windows startup  [{startup_status}]",
            "Toggle", toggle_startup, GREEN if not task_status.get("startup") else RED)
        row("Boot-time Quick Scan", f"Quick Scan 1 min after every login  [{boot_status}]",
            "Toggle", toggle_boot_scan, GREEN if not task_status.get("boot_scan") else RED)

        tk.Label(win, text="Note: Startup tasks require Windows Task Scheduler (built-in).",
                  font=("Segoe UI", 8), bg=BG, fg=TEXT_DIM, padx=20).pack(anchor="w", pady=(10, 0))

    def toggle_honeypot(self):
        if self._honeypot_observer and self._honeypot_observer.is_alive():
            self._honeypot_observer.stop()
            self._honeypot_observer = None
            self.honeypot_btn.config(text="🍯 Start Honeypot", bg=GREEN)
            self.honeypot_btn._bg = GREEN
            self._log("Honeypot guard stopped.", "dim")
        else:
            def on_trigger(alert):
                self.root.after(0, lambda: self._log(f"🚨 HONEYPOT TRIGGERED: {alert['message']}", "infected"))
            self._honeypot_observer = honeypot.start_honeypot_guard(on_trigger=on_trigger)
            count = len(honeypot._load_meta())
            self.honeypot_btn.config(text="■ Stop Honeypot", bg=RED)
            self.honeypot_btn._bg = RED
            self._log(f"Honeypot active — {count} decoy files deployed. Any ransomware touching them will be caught.", "clean")

    def toggle_usb_guard(self):
        if self._usb_thread and self._usb_thread.is_alive():
            self._usb_stop.set()
            self.usb_btn.config(text="💾 USB Auto-Scan", bg=GREEN)
            self.usb_btn._bg = GREEN
            self._log("USB Guard stopped.", "dim")
        else:
            self._usb_stop.clear()
            def on_new_drive(drive):
                self.root.after(0, lambda: self._log(f"💾 New USB detected: {drive} — scanning...", "suspicious"))
                summary = scanner.custom_scan(drive, auto_quarantine=self.auto_quarantine_var.get())
                self.root.after(0, lambda: self._show_summary(summary, 0, f"USB Scan ({drive})"))
            def worker():
                usb_guard.start_usb_guard(on_new_drive=on_new_drive)
            self._usb_thread = threading.Thread(target=worker, daemon=True)
            self._usb_thread.start()
            self.usb_btn.config(text="■ Stop USB Guard", bg=RED)
            self.usb_btn._bg = RED
            self._log("USB Guard active — new drives will be auto-scanned on connection.", "clean")

    def toggle_network_monitor(self):
        if self._network_thread and self._network_thread.is_alive():
            self._network_stop.set()
            self.net_btn.config(text="🌐 Network Monitor", bg=GREEN)
            self.net_btn._bg = GREEN
            self._log("Network Monitor stopped.", "dim")
        else:
            self._network_stop.clear()
            if not network_monitor._load_blocklist()["ips"]:
                self._log("Downloading IP blocklist from abuse.ch...", "dim")
                threading.Thread(target=lambda: network_monitor.update_blocklist(
                    lambda m: self.root.after(0, lambda msg=m: self._log(f"  {msg}", "dim"))
                ), daemon=True).start()
            def on_threat(item):
                self.root.after(0, lambda: self._log(
                    f"🚨 MALICIOUS CONNECTION: {item['process']} → {item['remote_ip']}:{item['remote_port']} ({item['malware']})",
                    "infected"))
            def worker():
                network_monitor.start_network_monitor(on_threat=on_threat)
            self._network_thread = threading.Thread(target=worker, daemon=True)
            self._network_thread.start()
            self.net_btn.config(text="■ Stop Network Monitor", bg=RED)
            self.net_btn._bg = RED
            self._log("Network Monitor active — outbound connections checked against malicious IP list.", "clean")

    def toggle_self_protect(self):
        if self._self_protect_observer and self._self_protect_observer.is_alive():
            self._self_protect_observer.stop()
            self._self_protect_observer = None
            self.selfp_btn.config(text="🔒 Self-Protect", bg=GREEN)
            self.selfp_btn._bg = GREEN
            self._log("Self-Protection stopped.", "dim")
        else:
            def on_tamper(alert):
                self.root.after(0, lambda: self._log(f"🚨 {alert['message']}", "infected"))
            self._self_protect_observer = self_protect.start_self_protection(on_tamper=on_tamper)
            self.selfp_btn.config(text="■ Self-Protected", bg=RED)
            self.selfp_btn._bg = RED
            self._log("Self-Protection active — SkyAV files are now monitored against tampering.", "clean")

    def toggle_download_guard(self):
        if self._download_guard_observer and self._download_guard_observer.is_alive():
            self._download_guard_observer.stop()
            self._download_guard_observer = None
            self.dlguard_btn.config(text="⬇ Download Guard", bg=GREEN)
            self.dlguard_btn._bg = GREEN
            self._log("Download Guard stopped.", "dim")
        else:
            def on_verdict(result):
                if result["status"] in ("infected", "suspicious"):
                    self.root.after(0, lambda: self._log(
                        f"🚨 Downloaded file auto-quarantined: {os.path.basename(result['path'])} — {result['detail']}",
                        "infected"))
                else:
                    self.root.after(0, lambda: self._log(
                        f"⬇ Download scanned clean: {os.path.basename(result['path'])}", "dim"))
            self._download_guard_observer = download_guard.start_download_guard(on_verdict=on_verdict, auto_action=True)
            self.dlguard_btn.config(text="■ Guarding Downloads", bg=RED)
            self.dlguard_btn._bg = RED
            self._log("Download Guard active — new files in Downloads are scanned the instant they land.", "clean")

    def run_browser_guard(self):
        self._log("Checking hosts file, browser extensions, homepage/search settings...", "dim")
        def worker():
            result = browser_guard.run_full_check()
            def show():
                if result["clean"]:
                    self._log("Browser Guard: no hijacking indicators found. ✅", "clean")
                else:
                    self._log(f"Browser Guard: {len(result['findings'])} issue(s) found:", "infected")
                    for f in result["findings"]:
                        self._log(f"  [{f['type']}] {f['detail']}", "infected")
            self.root.after(0, show)
        threading.Thread(target=worker, daemon=True).start()

    def open_cmd_analyzer(self):
        """Full-featured AI Command Analyzer with tabs, risk score, VT, history, export."""
        win = tk.Toplevel(self.root)
        win.title("🔍 AI Command Analyzer")
        win.geometry("960x720")
        win.configure(bg=BG)
        win.resizable(True, True)
        win.minsize(800, 600)

        # ── Header ────────────────────────────────────────────────────────
        hdr = tk.Frame(win, bg=BG)
        hdr.pack(fill="x", padx=22, pady=(16,0))
        tk.Label(hdr, text="AI Command Analyzer", font=("Segoe UI",17,"bold"), bg=BG, fg=TEXT).pack(side="left")
        tk.Label(hdr, text="  Powered by Gemini AI", font=("Segoe UI",9), bg=BG, fg=TEXT_DIM).pack(side="left", pady=4)

        # ── Notebook tabs ─────────────────────────────────────────────────
        style = ttk.Style()
        style.theme_use("default")
        style.configure("TNotebook",       background=BG,       borderwidth=0)
        style.configure("TNotebook.Tab",   background=BG_PANEL, foreground=TEXT_DIM,
                        padding=[14,6],    font=("Segoe UI",10))
        style.map("TNotebook.Tab",
                  background=[("selected", ACCENT)],
                  foreground=[("selected", "#fff")])

        nb = ttk.Notebook(win)
        nb.pack(fill="both", expand=True, padx=22, pady=(12,0))

        tab_single  = tk.Frame(nb, bg=BG)
        tab_batch   = tk.Frame(nb, bg=BG)
        tab_history = tk.Frame(nb, bg=BG)
        nb.add(tab_single,  text="  🔍 Analyze  ")
        nb.add(tab_batch,   text="  📋 Batch  ")
        nb.add(tab_history, text="  🕐 History  ")

        # ════════════════════════════════════════════════════════════════
        # TAB 1 — SINGLE ANALYZE
        # ════════════════════════════════════════════════════════════════
        left  = tk.Frame(tab_single, bg=BG, width=360)
        left.pack(side="left", fill="y", padx=(0,8), pady=12)
        left.pack_propagate(False)
        right = tk.Frame(tab_single, bg=BG)
        right.pack(side="left", fill="both", expand=True, pady=12)

        # — Input —
        tk.Label(left, text="COMMAND", font=("Segoe UI",9,"bold"), bg=BG, fg=TEXT_DIM).pack(anchor="w")
        cmd_frame = tk.Frame(left, bg=BORDER, bd=1)
        cmd_frame.pack(fill="x", pady=(4,8))
        cmd_entry = tk.Text(cmd_frame, height=4, font=("Cascadia Code",10),
                            bg=BG_LOG, fg=TEXT, insertbackground=TEXT,
                            relief="flat", bd=0, padx=10, pady=8, wrap="word")
        cmd_entry.pack(fill="x")

        # — Risk Score gauge —
        risk_frame = tk.Frame(left, bg=BG_CARD, padx=14, pady=12)
        risk_frame.pack(fill="x", pady=(0,8))
        risk_top = tk.Frame(risk_frame, bg=BG_CARD)
        risk_top.pack(fill="x")
        tk.Label(risk_top, text="RISK SCORE", font=("Segoe UI",9,"bold"), bg=BG_CARD, fg=TEXT_DIM).pack(side="left")
        risk_val_lbl = tk.Label(risk_top, text="—", font=("Segoe UI",22,"bold"), bg=BG_CARD, fg=TEXT_DIM)
        risk_val_lbl.pack(side="right")
        risk_bar_bg = tk.Frame(risk_frame, bg=BORDER, height=6)
        risk_bar_bg.pack(fill="x", pady=(6,0))
        risk_bar    = tk.Frame(risk_bar_bg, bg=BORDER, height=6, width=0)
        risk_bar.place(x=0, y=0, relheight=1)

        verdict_lbl = tk.Label(left, text="", font=("Segoe UI",10,"bold"), bg=BG, fg=TEXT_DIM, wraplength=330, justify="left")
        verdict_lbl.pack(anchor="w", pady=(0,8))

        # — VT results —
        tk.Label(left, text="VIRUSTOTAL IOC CHECK", font=("Segoe UI",9,"bold"), bg=BG, fg=TEXT_DIM).pack(anchor="w")
        vt_frame = tk.Frame(left, bg=BORDER, bd=1)
        vt_frame.pack(fill="x", pady=(4,8))
        vt_text = tk.Text(vt_frame, height=5, font=("Cascadia Code",8),
                          bg=BG_LOG, fg=TEXT_DIM, relief="flat", bd=0,
                          padx=8, pady=6, wrap="word", state="disabled")
        vt_text.pack(fill="x")

        # — Buttons —
        btn_row = tk.Frame(left, bg=BG)
        btn_row.pack(fill="x", pady=(4,0))
        analyze_btn = RoundButton(btn_row, "🔍 Analyze", lambda: _do_analyze(), bg=ACCENT, fg="#fff")
        analyze_btn.pack(side="left", padx=(0,8))
        export_btn  = RoundButton(btn_row, "💾 Export", lambda: _do_export(), bg=BG_PANEL, fg=TEXT)
        export_btn.pack(side="left")

        # — Analysis output —
        tk.Label(right, text="AI ANALYSIS", font=("Segoe UI",9,"bold"), bg=BG, fg=TEXT_DIM).pack(anchor="w")
        out_wrap = tk.Frame(right, bg=BORDER, bd=1)
        out_wrap.pack(fill="both", expand=True, pady=(4,0))
        out_text = tk.Text(out_wrap, wrap="word", font=("Segoe UI",10),
                           bg=BG_LOG, fg=TEXT, insertbackground=TEXT,
                           relief="flat", padx=14, pady=12, bd=0, state="disabled")
        out_text.pack(side="left", fill="both", expand=True)
        out_sb = ttk.Scrollbar(out_wrap, command=out_text.yview)
        out_sb.pack(side="right", fill="y")
        out_text.config(yscrollcommand=out_sb.set)
        out_text.tag_config("h",       foreground=ACCENT,  font=("Segoe UI",10,"bold"))
        out_text.tag_config("safe",    foreground=GREEN)
        out_text.tag_config("caution", foreground=ORANGE)
        out_text.tag_config("danger",  foreground=RED)
        out_text.tag_config("dim",     foreground=TEXT_DIM)
        out_text.tag_config("decoded", foreground=ACCENT2, font=("Cascadia Code",9))

        _last_result = [None]

        SECTION_HEADERS = {
            "COMMAND BREAKDOWN", "WHAT IT DOES", "WHERE IT AFFECTS THE PC",
            "MITRE ATT&CK MAPPING", "RISK SCORE", "SIMILAR MALWARE",
            "PROS / LEGITIMATE USES", "PROS", "CONS / RISKS", "CONS",
            "REMEDIATION", "SAFETY VERDICT",
        }

        def _render_analysis(result: dict):
            out_text.config(state="normal")
            out_text.delete("1.0", "end")
            dec = result.get("decoded")
            if dec:
                out_text.insert("end", "🔓 DECODED PAYLOAD\n", "h")
                out_text.insert("end", dec + "\n\n", "decoded")
            for line in result.get("analysis","").splitlines():
                stripped = line.strip()
                upper    = stripped.upper()
                if any(upper.startswith(h) for h in SECTION_HEADERS):
                    out_text.insert("end", "\n" + stripped + "\n", "h")
                elif "✅" in stripped:
                    out_text.insert("end", stripped + "\n", "safe")
                elif "⚠" in stripped:
                    out_text.insert("end", stripped + "\n", "caution")
                elif "🚨" in stripped:
                    out_text.insert("end", stripped + "\n", "danger")
                else:
                    out_text.insert("end", line + "\n")
            out_text.config(state="disabled")
            out_text.see("1.0")

        def _update_risk(score: int):
            if score < 0:
                risk_val_lbl.config(text="—", fg=TEXT_DIM)
                risk_bar.config(bg=BORDER, width=0)
                return
            color = GREEN if score < 35 else (ORANGE if score < 70 else RED)
            risk_val_lbl.config(text=str(score), fg=color)
            risk_bar_bg.update_idletasks()
            bar_w = int(risk_bar_bg.winfo_width() * score / 100)
            risk_bar.config(bg=color, width=max(bar_w, 1))
            risk_bar.place(x=0, y=0, relheight=1, width=max(bar_w,1))

        def _update_vt(vt_results: list):
            vt_text.config(state="normal")
            vt_text.delete("1.0", "end")
            for v in vt_results:
                icon = "🚨" if "MALICIOUS" in v.get("result","") else ("✅" if "CLEAN" in v.get("result","") else "ℹ")
                vt_text.insert("end", f"{icon} [{v.get('type','?')}] {v.get('ioc','')}\n   → {v.get('result','')}\n")
            vt_text.config(state="disabled")

        def _do_analyze(cmdlines=None, batch_out=None):
            """Single or batch analyze. batch_out=Text widget for batch tab."""
            if cmdlines is None:
                cmdline = cmd_entry.get("1.0","end").strip()
                if not cmdline:
                    return
                cmdlines = [cmdline]
                is_single = True
            else:
                is_single = False

            analyze_btn.config(state="disabled", text="Analyzing…")
            if is_single:
                out_text.config(state="normal")
                out_text.delete("1.0","end")
                out_text.insert("end","🤖 Analyzing…\n","h")
                out_text.config(state="disabled")
                risk_val_lbl.config(text="…", fg=TEXT_DIM)
                verdict_lbl.config(text="")
                vt_text.config(state="normal"); vt_text.delete("1.0","end"); vt_text.config(state="disabled")

            def worker():
                import cmd_monitor as _cm
                results = []
                for cmd in cmdlines:
                    dec_info = _cm.decode_command(cmd)
                    r = cmd_analyzer.analyze(cmd, dec_info.get("decoded"))
                    r["decoded"] = dec_info.get("decoded")
                    cmd_analyzer.save_to_history(r)
                    results.append(r)

                def show():
                    analyze_btn.config(state="normal", text="🔍 Analyze")
                    if is_single and results:
                        r = results[0]
                        _last_result[0] = r
                        _render_analysis(r)
                        _update_risk(r.get("risk_score", -1))
                        _update_vt(r.get("vt_results", []))
                        verd = r.get("verdict","")
                        tag  = "safe" if "✅" in verd else ("caution" if "⚠" in verd else "danger")
                        verdict_lbl.config(text=verd,
                            fg=GREEN if tag=="safe" else (ORANGE if tag=="caution" else RED))
                        # refresh history tab
                        _load_history_tab()
                    elif not is_single and batch_out:
                        batch_out.config(state="normal")
                        batch_out.delete("1.0","end")
                        for r in results:
                            score = r.get("risk_score",-1)
                            verd  = r.get("verdict","")
                            batch_out.insert("end",
                                f"{'─'*60}\nCOMMAND: {r.get('cmdline','')[:80]}\n"
                                f"RISK: {score}/100    {verd}\n\n")
                        batch_out.config(state="disabled")
                        _load_history_tab()

                win.after(0, show)

            threading.Thread(target=worker, daemon=True).start()

        def _do_export():
            r = _last_result[0]
            if not r:
                messagebox.showinfo("Nothing to export", "Run an analysis first.")
                return
            fp = filedialog.asksaveasfilename(
                defaultextension=".txt",
                filetypes=[("Text files","*.txt"),("All files","*.*")],
                initialfile=f"skyav_cmd_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
            )
            if fp:
                ok = cmd_analyzer.export_report(r, fp)
                if ok:
                    messagebox.showinfo("Exported", f"Report saved to:\n{fp}")
                else:
                    messagebox.showerror("Error", "Could not save report.")

        cmd_entry.focus_set()

        # ════════════════════════════════════════════════════════════════
        # TAB 2 — BATCH ANALYZE
        # ════════════════════════════════════════════════════════════════
        tk.Label(tab_batch, text="Paste multiple commands (one per line):",
                 font=("Segoe UI",10), bg=BG, fg=TEXT_DIM).pack(anchor="w", padx=16, pady=(14,4))
        batch_in_frame = tk.Frame(tab_batch, bg=BORDER, bd=1)
        batch_in_frame.pack(fill="x", padx=16, pady=(0,8))
        batch_in = tk.Text(batch_in_frame, height=6, font=("Cascadia Code",9),
                           bg=BG_LOG, fg=TEXT, insertbackground=TEXT,
                           relief="flat", bd=0, padx=10, pady=8, wrap="none")
        batch_in.pack(fill="x")

        batch_btn_row = tk.Frame(tab_batch, bg=BG)
        batch_btn_row.pack(fill="x", padx=16, pady=(0,8))
        batch_out_frame = tk.Frame(tab_batch, bg=BORDER, bd=1)
        batch_out_frame.pack(fill="both", expand=True, padx=16, pady=(0,16))
        batch_out = tk.Text(batch_out_frame, wrap="word", font=("Segoe UI",9),
                            bg=BG_LOG, fg=TEXT, relief="flat", bd=0,
                            padx=10, pady=8, state="disabled")
        batch_out.pack(side="left", fill="both", expand=True)
        batch_sb = ttk.Scrollbar(batch_out_frame, command=batch_out.yview)
        batch_sb.pack(side="right", fill="y")
        batch_out.config(yscrollcommand=batch_sb.set)

        def _do_batch():
            cmds = [c for c in batch_in.get("1.0","end").splitlines() if c.strip()]
            if not cmds:
                return
            analyze_btn.config(state="disabled", text="Analyzing…")
            _do_analyze(cmdlines=cmds, batch_out=batch_out)

        RoundButton(batch_btn_row, "📋 Analyze All", _do_batch, bg=ACCENT, fg="#fff").pack(side="left")

        # ════════════════════════════════════════════════════════════════
        # TAB 3 — HISTORY
        # ════════════════════════════════════════════════════════════════
        hist_top = tk.Frame(tab_history, bg=BG)
        hist_top.pack(fill="x", padx=16, pady=(12,4))
        tk.Label(hist_top, text="Last 100 analyzed commands", font=("Segoe UI",9), bg=BG, fg=TEXT_DIM).pack(side="left")
        RoundButton(hist_top, "🗑 Clear History", lambda: [cmd_analyzer.clear_history(), _load_history_tab()],
                    bg=RED, fg="#fff").pack(side="right")

        hist_frame = tk.Frame(tab_history, bg=BORDER, bd=1)
        hist_frame.pack(fill="both", expand=True, padx=16, pady=(0,16))
        hist_text = tk.Text(hist_frame, wrap="word", font=("Cascadia Code",9),
                            bg=BG_LOG, fg=TEXT, relief="flat", bd=0, padx=10, pady=8)
        hist_text.pack(side="left", fill="both", expand=True)
        hist_sb = ttk.Scrollbar(hist_frame, command=hist_text.yview)
        hist_sb.pack(side="right", fill="y")
        hist_text.config(yscrollcommand=hist_sb.set)
        hist_text.tag_config("ts",      foreground=TEXT_DIM, font=("Segoe UI",8))
        hist_text.tag_config("cmd",     foreground=ACCENT2,  font=("Cascadia Code",9,"bold"))
        hist_text.tag_config("safe",    foreground=GREEN)
        hist_text.tag_config("caution", foreground=ORANGE)
        hist_text.tag_config("danger",  foreground=RED)

        def _load_history_tab():
            hist_text.config(state="normal")
            hist_text.delete("1.0","end")
            history = cmd_analyzer.get_history()
            if not history:
                hist_text.insert("end","No commands analyzed yet.\n","ts")
            for entry in history:
                ts    = entry.get("timestamp","")
                cmd   = entry.get("cmdline","")[:100]
                score = entry.get("risk_score",-1)
                verd  = entry.get("verdict","")
                tag   = "safe" if "✅" in verd else ("caution" if "⚠" in verd else "danger")
                hist_text.insert("end", f"{ts}\n", "ts")
                hist_text.insert("end", f"  {cmd}\n", "cmd")
                hist_text.insert("end",
                    f"  Risk: {score}/100   {verd}\n\n", tag)
            hist_text.config(state="disabled")

        _load_history_tab()

        import datetime


    def toggle_cmd_monitor(self):
        if self._cmd_monitor and self._cmd_monitor.is_alive():
            self._cmd_monitor.stop()
            self._cmd_monitor = None
            self.cmdmon_btn.set_bg(GREEN)
            self.cmdmon_btn.config(text="💻 CMD Monitor")
            self._log("CMD Monitor stopped.", "dim")
        else:
            def on_alert(result):
                name    = result.get("process_name", "unknown")
                pid     = result.get("pid", 0)
                cmdline = result.get("cmdline", "")
                hits    = result.get("hits", [])
                decode  = result.get("decode", {})
                sev     = result.get("max_severity", "medium")
                tag     = "infected" if sev == "high" else "suspicious"

                lines = [f"🚨 CMD ALERT [{name} PID:{pid}]"]
                lines.append(f"   Command: {cmdline[:200]}")
                for h in hits:
                    lines.append(f"   ⚠ [{h['severity'].upper()}] {h['description']}")
                if decode.get("decoded"):
                    lines.append(f"   🔓 Decoded ({decode['method']}): {decode['decoded'][:200]}")

                # Auto AI analysis for HIGH severity
                if sev == "high":
                    lines.append("   🤖 Running AI analysis...")

                msg = "\n".join(lines)
                self.root.after(0, lambda m=msg, t=tag: self._log(m, t))

                # Auto-analyze high severity commands in background
                if sev == "high":
                    def auto_analyze(cl=cmdline, dc=decode.get("decoded")):
                        analysis = cmd_analyzer.analyze(cl, dc)
                        verdict_line = ""
                        # Try to find verdict emoji directly in any line
                        for line in analysis.splitlines():
                            stripped = line.strip()
                            if any(x in stripped for x in ("✅", "⚠️", "⚠", "🚨")):
                                verdict_line = stripped
                                break
                        if verdict_line:
                            tag = "clean" if "✅" in verdict_line else ("suspicious" if ("⚠" in verdict_line or "⚠️" in verdict_line) else "infected")
                            self.root.after(0, lambda l=f"   🤖 AI Verdict: {verdict_line[:150]}", t=tag: self._log(l, t))
                        else:
                            self.root.after(0, lambda: self._log("   🤖 AI analysis complete (open Analyze Command for full details).", "dim"))
                    threading.Thread(target=auto_analyze, daemon=True).start()

            self._cmd_monitor = cmd_monitor.CmdMonitor(on_alert=on_alert)
            self._cmd_monitor.start()
            self.cmdmon_btn.set_bg(RED)
            self.cmdmon_btn.config(text="■ CMD Monitoring")
            self._log("CMD Monitor active — watching PowerShell, CMD, and script processes.", "clean")

            self._cmd_monitor = cmd_monitor.CmdMonitor(on_alert=on_alert)
            self._cmd_monitor.start()
            self.cmdmon_btn.set_bg(RED)
            self.cmdmon_btn.config(text="■ CMD Monitoring")
            self._log("CMD Monitor active — watching PowerShell, CMD, and script processes.", "clean")


        self._log("Checking hosts file, browser extensions, homepage/search settings...", "dim")
        def worker():
            result = browser_guard.run_full_check()
            def show():
                if result["clean"]:
                    self._log("Browser Guard: no hijacking indicators found. ✅", "clean")
                else:
                    self._log(f"Browser Guard: {len(result['findings'])} issue(s) found:", "infected")
                    for f in result["findings"]:
                        self._log(f"  [{f['type']}] {f['detail']}", "infected")
            self.root.after(0, show)
        threading.Thread(target=worker, daemon=True).start()

    def open_startup_manager(self):
        win = tk.Toplevel(self.root)
        win.title("🚀 Startup Manager")
        win.geometry("700x480")
        win.configure(bg=BG)

        tk.Label(win, text="Startup Manager", font=("Segoe UI", 16, "bold"), bg=BG, fg=TEXT).pack(anchor="w", padx=20, pady=(16, 4))
        tk.Label(win, text="Programs configured to launch automatically when Windows starts.",
                 font=("Segoe UI", 9), bg=BG, fg=TEXT_DIM, wraplength=640, justify="left").pack(anchor="w", padx=20)

        _, list_frame = self._make_scrollable(win)

        items = startup_manager.flag_suspicious(startup_manager.list_startup_items())

        if not items:
            tk.Label(list_frame, text="No startup entries found.", bg=BG, fg=TEXT_DIM).pack(anchor="w", pady=10)

        for item in items:
            row = tk.Frame(list_frame, bg=BG_PANEL, bd=1)
            row.pack(fill="x", pady=4)

            color = RED if item.get("is_suspicious") else TEXT
            text = f"{item['name']}  —  {item['command']}"
            tk.Label(row, text=text, font=("Cascadia Code", 9), bg=BG_PANEL, fg=color,
                     wraplength=480, justify="left", anchor="w").pack(side="left", padx=10, pady=8, fill="x", expand=True)

            if item.get("reason"):
                tk.Label(row, text=item["reason"], font=("Segoe UI", 8, "italic"), bg=BG_PANEL, fg=ORANGE,
                         wraplength=150, justify="left").pack(side="left", padx=6)

            def make_disable(it=item, r=row):
                def do_disable():
                    if startup_manager.disable_startup_item(it):
                        self._log(f"Disabled startup entry: {it['name']}", "clean")
                        r.destroy()
                    else:
                        messagebox.showerror("Failed", "Could not disable this entry (try running SkyAV as Administrator).")
                return do_disable

            RoundButton(row, "Disable", make_disable(), bg=RED, fg="#0d0e14").pack(side="right", padx=10, pady=8)

    def open_task_scanner(self):
        win = tk.Toplevel(self.root)
        win.title("📅 Scheduled Task Scanner")
        win.geometry("700x480")
        win.configure(bg=BG)

        tk.Label(win, text="Scheduled Task Scanner", font=("Segoe UI", 16, "bold"), bg=BG, fg=TEXT).pack(anchor="w", padx=20, pady=(16, 4))
        status_label = tk.Label(win, text="Scanning Windows Scheduled Tasks...", font=("Segoe UI", 9), bg=BG, fg=TEXT_DIM)
        status_label.pack(anchor="w", padx=20)

        _, list_frame = self._make_scrollable(win)

        def worker():
            tasks = task_scanner.flag_suspicious_tasks()
            def show():
                status_label.config(text=f"{len(tasks)} task(s) scanned.")
                flagged = [t for t in tasks if t["is_suspicious"]]
                if not flagged:
                    tk.Label(list_frame, text="No suspicious scheduled tasks found. ✅", bg=BG, fg=GREEN).pack(anchor="w", pady=10)
                for t in flagged:
                    row = tk.Frame(list_frame, bg=BG_PANEL, bd=1)
                    row.pack(fill="x", pady=4)
                    name = t.get("TaskName", "Unknown")
                    cmd = t.get("Task To Run", "")
                    reasons = "; ".join(t["reasons"])
                    tk.Label(row, text=f"{name}\n{cmd}\n⚠ {reasons}", font=("Cascadia Code", 9), bg=BG_PANEL, fg=RED,
                             wraplength=630, justify="left", anchor="w").pack(anchor="w", padx=10, pady=8)
            self.root.after(0, show)
        threading.Thread(target=worker, daemon=True).start()

    def create_restore_point(self):
        self._log("Creating System Restore Point...", "dim")
        def worker():
            result = restore_point.create_restore_point("SkyAV manual checkpoint")
            def show():
                if result["success"]:
                    self._log("System Restore Point created successfully.", "clean")
                else:
                    self._log(f"Restore Point failed: {result['message']}", "infected")
            self.root.after(0, show)
        threading.Thread(target=worker, daemon=True).start()

    def open_threat_hunter(self):
        win = tk.Toplevel(self.root)
        win.title("🤖 AI Threat Hunter")
        win.geometry("620x500")
        win.configure(bg=BG)

        tk.Label(win, text="🤖 AI Threat Hunter", font=("Segoe UI", 14, "bold"),
                  bg=BG, fg=TEXT, padx=20, pady=12).pack(anchor="w")
        tk.Label(win, text="Describe what seems suspicious — AI will analyze your running system and report findings.",
                  font=("Segoe UI", 9), bg=BG, fg=TEXT_DIM, padx=20).pack(anchor="w")
        tk.Label(win, text='Examples: "my PC fan is loud when idle" / "something is accessing my mic" / "internet is slow"',
                  font=("Segoe UI", 8, "italic"), bg=BG, fg=TEXT_DIM, padx=20).pack(anchor="w", pady=(2, 10))

        input_frame = tk.Frame(win, bg=BG, padx=20)
        input_frame.pack(fill="x")
        entry = tk.Text(input_frame, height=3, font=("Segoe UI", 10), bg=BG_LOG,
                         fg=TEXT, insertbackground=TEXT, relief="flat", padx=8, pady=6, bd=1)
        entry.pack(fill="x", pady=(0, 8))

        result_frame = tk.Frame(win, bg=BG, padx=20)
        result_frame.pack(fill="both", expand=True)
        result_text = tk.Text(result_frame, wrap="word", font=("Cascadia Code", 9),
                               bg=BG_LOG, fg=TEXT, relief="flat", padx=10, pady=8, state="disabled")
        result_text.pack(fill="both", expand=True)

        def _log_result(msg, color=TEXT):
            result_text.config(state="normal")
            result_text.insert("end", msg + "\n")
            result_text.see("end")
            result_text.config(state="disabled")

        def do_hunt():
            query = entry.get("1.0", "end").strip()
            if not query:
                return
            result_text.config(state="normal")
            result_text.delete("1.0", "end")
            result_text.config(state="disabled")
            _log_result("🔍 Collecting system data and analyzing...", TEXT_DIM)
            hunt_btn.config(state="disabled")

            def worker():
                result = threat_hunter.hunt(query, self._last_summary)
                self.root.after(0, lambda: (
                    _log_result("\n" + result),
                    hunt_btn.config(state="normal")
                ))

            threading.Thread(target=worker, daemon=True).start()

        hunt_btn = RoundButton(input_frame, "🔍 Hunt Now", do_hunt, bg=ACCENT, fg="#0d0e14")
        hunt_btn.pack(anchor="e")

    def review_flagged(self):
        if not self._last_summary or not self._last_summary.get("flagged"):
            messagebox.showinfo("Review Flagged Files", "No flagged files from the last scan. Run a scan first.")
            return

        win = tk.Toplevel(self.root)
        win.title("Review Flagged Files")
        win.geometry("680x460")
        win.configure(bg=BG)

        tk.Label(win, text="Flagged Files", font=("Segoe UI", 13, "bold"),
                  bg=BG, fg=TEXT, padx=15, pady=12).pack(anchor="w")
        tk.Label(win, text="If you're sure a file is safe, mark it — it won't be flagged again.",
                  font=("Segoe UI", 9), bg=BG, fg=TEXT_DIM, padx=15).pack(anchor="w", pady=(0, 8))

        canvas_frame = tk.Frame(win, bg=BG)
        canvas_frame.pack(fill="both", expand=True, padx=15, pady=(0, 15))
        canvas, scroll_frame = self._make_scrollable(canvas_frame)

        for item in self._last_summary["flagged"]:
            row = tk.Frame(scroll_frame, bg=BG_PANEL, padx=10, pady=8)
            row.pack(fill="x", pady=4)
            if hasattr(scroll_frame, '_bind_children'):
                scroll_frame._bind_children(row)

            text_frame = tk.Frame(row, bg=BG_PANEL)
            text_frame.pack(side="left", fill="x", expand=True)
            tk.Label(text_frame, text=os.path.basename(item["path"]),
                      font=("Segoe UI", 10, "bold"), bg=BG_PANEL, fg=TEXT, anchor="w").pack(fill="x")
            tk.Label(text_frame, text=item["path"], font=("Segoe UI", 8),
                      bg=BG_PANEL, fg=TEXT_DIM, anchor="w", wraplength=420, justify="left").pack(fill="x")
            tk.Label(text_frame, text=item["detail"], font=("Segoe UI", 8),
                      bg=BG_PANEL, fg=ORANGE, anchor="w", wraplength=420, justify="left").pack(fill="x")

            def make_mark_safe(path=item["path"], name=os.path.basename(item["path"]), row=row):
                def action():
                    success = whitelist.add_to_whitelist(path, "Manually marked safe by user")
                    if success:
                        self._log(f"Marked as safe: {name}", "clean")
                        row.destroy()
                    else:
                        messagebox.showerror("Error", "Could not whitelist — file may have been moved or deleted.")
                return action

            RoundButton(row, "✓ Mark as Safe", make_mark_safe(), bg=GREEN, fg="#0d0e14").pack(side="right")

    def view_history(self):
        history = logger.read_history(limit=10)
        self._log("\n=== Recent Scan History ===", "heading")
        if not history:
            self._log("  (no scans yet)", "dim")
        for entry in history:
            self._log(f"  {entry['timestamp']} | {entry['scan_type']} | "
                       f"scanned={entry['scanned']} infected={entry['infected']} suspicious={entry['suspicious']}", "dim")


    # ---------- SYSTEM TRAY ----------
    def _setup_tray(self):
        self.tray = tray_icon.TrayIcon(
            on_open=self._restore_from_tray,
            on_exit=self._true_exit,
            on_quick_scan=self.run_quick_scan,
        )
        self.tray.start()
        alerts.register_desktop_notifier(lambda title, msg: self.tray.notify(msg, title))

    def _minimize_to_tray(self):
        """Called when the user clicks the window's X button — hides instead of closing,
        so real-time protection and registry guard keep running in the background."""
        self.root.withdraw()
        self._log("SkyAV minimized to system tray. Protection keeps running.", "dim")

    def _restore_from_tray(self):
        self.root.after(0, self.root.deiconify)
        self.root.after(0, self.root.lift)

    def _true_exit(self):
        """Called from the tray menu's 'Exit' — fully stops everything and closes the app."""
        self.monitor_stop_flag.set()
        self.guard_stop_flag.set()
        self.root.after(0, self.root.destroy)


def launch():
    root = tk.Tk()
    app = SkyAVApp(root)
    root.mainloop()


if __name__ == "__main__":
    launch()
