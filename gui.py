#!/usr/bin/env python3
"""
Little-Sandbox - Tkinter front-end for the Active Threat Interceptor.

Put this file next to interceptor.py (or interceptor_v2.py) and run it with
the system Python, because the interceptor refuses venv/pyenv interpreters:

    /usr/bin/python3 interceptor_gui.py

The GUI launches the interceptor as a subprocess and parses its terminal
output, so the sandbox logic itself is untouched.
Needs: Linux, bubblewrap (apt install bubblewrap), python3-tk.
"""
import os
import queue
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, font, messagebox, ttk

HERE = os.path.dirname(os.path.realpath(__file__))

ANSI = re.compile(r"\x1b\[[0-9;]*m")
TS_LINE = re.compile(r"^\[\s*(\d+\.\d+)\]\s+(\S+)\s*(.*)$")
TARGET_LINE = re.compile(r"^\s+\| (stdout|stderr): ?(.*)$")

C = dict(
    bg="#14161b", surface="#1b1e25", panel="#171a20", field="#101217",
    raised="#252932", border="#2c313b",
    text="#d7dbe2", muted="#8b93a1", faint="#586070",
    accent="#5f8fd4", accent_dim="#2a3a57", select="#2d3a52",
    ok="#6fae86", warn="#d4a24c", bad="#d9695f",
)
VERDICT_COLOR = {"BENIGN": "ok", "SUSPICIOUS": "warn", "BLOCKED": "bad", "MALICIOUS": "bad"}

MODE_HINT = {
    "observe": "Everything is logged and the script keeps running. "
               "Native-code escapes are still denied.",
    "strict": "Dangerous calls (spawn, kill, chmod, rmtree...) are blocked "
              "the moment they happen.",
}


def find_interceptor():
    for name in ("interceptor.py", "interceptor_v2.py"):
        p = os.path.join(HERE, name)
        if os.path.isfile(p):
            return p
    return ""


class Flat(tk.Button):
    """Flat button with a hover colour and a proper disabled look."""
    KINDS = {
        "primary": dict(bg=C["accent"], fg="#0d1117", hover="#79a2e0", dbg=C["raised"], dfg=C["faint"]),
        "danger": dict(bg="#3a2427", fg=C["bad"], hover="#4b2c30", dbg=C["raised"], dfg=C["faint"]),
        "soft": dict(bg=C["raised"], fg=C["text"], hover="#313745", dbg=C["raised"], dfg=C["faint"]),
        "ghost": dict(bg=C["bg"], fg=C["muted"], hover=C["raised"], dbg=C["bg"], dfg=C["faint"]),
    }

    def __init__(self, parent, text, command, kind="soft", font=None, padx=12, pady=6, **over):
        k = dict(self.KINDS[kind])
        k.update(over)
        super().__init__(parent, text=text, command=command, font=font, bd=0, relief="flat",
                         highlightthickness=0, cursor="hand2", takefocus=0,
                         padx=padx, pady=pady, bg=k["bg"], fg=k["fg"],
                         activebackground=k["hover"], activeforeground=k["fg"],
                         disabledforeground=k["dfg"])
        self._k = k
        if "anchor" in over:
            self.configure(anchor=over["anchor"])
        self.bind("<Enter>", self._enter)
        self.bind("<Leave>", self._leave)

    def _enter(self, _):
        if str(self["state"]) != "disabled":
            self.configure(bg=self._k["hover"])

    def _leave(self, _):
        if str(self["state"]) != "disabled":
            self.configure(bg=self._k["bg"])

    def enable(self, on):
        k = self._k
        if on:
            self.configure(state="normal", bg=k["bg"], fg=k["fg"], cursor="hand2")
        else:
            self.configure(state="disabled", bg=k["dbg"], fg=k["dfg"], cursor="arrow")


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Little-Sandbox")
        self.geometry("1200x780")
        self.minsize(1000, 700)
        self.configure(bg=C["bg"])

        self.q = queue.Queue()
        self.proc = None
        self.t0 = None
        self.stopped = False
        self.timeout_s = 10.0
        self.counts = {"INFO": 0, "WARN": 0, "BLOCK": 0}
        self.err_tail = []
        self.notes_empty = True
        self.empty_shown = True

        self._fonts()
        self._style()
        self._vars()
        self._build()
        self._mode_hint()
        self._sync_analyst()
        self._apply_filter()
        self._idle_state()

        self.bind_all("<Control-Return>", lambda e: self.run())
        self.bind_all("<Escape>", lambda e: self.stop())
        self.bind_all("<Control-l>", lambda e: self.clear_log())
        self.protocol("WM_DELETE_WINDOW", self._close)
        self.after(40, self._pump)
        self.after(100, self._tick)

    # ------------------------------------------------------------ setup
    def _fonts(self):
        fams = set(font.families(self))

        def pick(names, fallback):
            for n in names:
                if n in fams:
                    return n
            return font.nametofont(fallback).actual("family")

        ui = pick(("Inter", "Noto Sans", "Cantarell", "Ubuntu", "DejaVu Sans"), "TkDefaultFont")
        mono = pick(("JetBrains Mono", "Fira Code", "Source Code Pro",
                     "DejaVu Sans Mono", "Liberation Mono"), "TkFixedFont")
        self.f_ui = font.Font(family=ui, size=10)
        self.f_bold = font.Font(family=ui, size=10, weight="bold")
        self.f_small = font.Font(family=ui, size=9)
        self.f_label = font.Font(family=ui, size=8, weight="bold")
        self.f_title = font.Font(family=ui, size=15, weight="bold")
        self.f_big = font.Font(family=ui, size=21, weight="bold")
        self.f_num = font.Font(family=mono, size=17, weight="bold")
        self.f_mono = font.Font(family=mono, size=10)
        self.f_mono_b = font.Font(family=mono, size=10, weight="bold")
        self.f_mono_s = font.Font(family=mono, size=9)

    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        for orient, sticky in (("Vertical", "ns"), ("Horizontal", "ew")):
            name = f"Dark.{orient}.TScrollbar"
            s.layout(name, [(f"{orient}.Scrollbar.trough", {
                "sticky": sticky,
                "children": [(f"{orient}.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"})]})])
            s.configure(name, background=C["raised"], troughcolor=C["panel"],
                        bordercolor=C["panel"], lightcolor=C["raised"],
                        darkcolor=C["raised"], gripcount=0, relief="flat", width=10)
            s.map(name, background=[("active", C["faint"]), ("pressed", C["faint"])])
        s.configure("Thin.Horizontal.TProgressbar", troughcolor=C["border"],
                    background=C["accent"], bordercolor=C["border"],
                    lightcolor=C["accent"], darkcolor=C["accent"], thickness=3)

    def _vars(self):
        self.v_icp = tk.StringVar(value=find_interceptor())
        self.v_target = tk.StringVar()
        self.v_args = tk.StringVar()
        self.v_timeout = tk.StringVar(value="10")
        self.v_maxev = tk.StringVar(value="20000")
        self.v_log = tk.StringVar()
        self.v_key = tk.StringVar(value=os.environ.get("GEMINI_API_KEY", ""))
        self.v_model = tk.StringVar(value=os.environ.get("ATI_MODEL", ""))
        self.v_mode = tk.StringVar(value="observe")
        self.v_net = tk.BooleanVar()
        self.v_analyze = tk.BooleanVar()
        self.v_status = tk.StringVar(value="Ready")
        self.v_verdict = tk.StringVar()
        self.v_sub = tk.StringVar()
        self.v_time = tk.StringVar()
        self.show = {k: tk.BooleanVar(value=True) for k in ("INFO", "WARN", "BLOCK", "target")}

    # ------------------------------------------------------------ widgets
    def _label(self, parent, text, font=None, fg=None, bg=None, **kw):
        return tk.Label(parent, text=text, font=font or self.f_ui, fg=fg or C["text"],
                        bg=bg or C["surface"], **kw)

    def _entry(self, parent, var, show=None, width=None):
        return tk.Entry(parent, textvariable=var, show=show or "", width=width or 20,
                        font=self.f_ui, bg=C["field"], fg=C["text"],
                        insertbackground=C["text"], relief="flat", bd=0,
                        highlightthickness=1, highlightbackground=C["border"],
                        highlightcolor=C["accent"], disabledbackground=C["surface"],
                        disabledforeground=C["faint"], selectbackground=C["select"],
                        selectforeground=C["text"])

    def _field(self, parent, label, var, browse=None, show=None):
        box = tk.Frame(parent, bg=C["surface"])
        box.pack(fill="x", pady=(0, 8))
        if label:
            self._label(box, label, self.f_small, C["muted"]).pack(anchor="w", pady=(0, 3))
        row = tk.Frame(box, bg=C["surface"])
        row.pack(fill="x")
        e = self._entry(row, var, show)
        e.pack(side="left", fill="x", expand=True, ipady=5)
        if browse:
            Flat(row, "Browse", browse, "soft", self.f_small, padx=10, pady=4).pack(
                side="left", padx=(6, 0), ipady=1)
        return e

    def _section(self, parent, title, top=16):
        f = tk.Frame(parent, bg=C["surface"])
        f.pack(fill="x", padx=18, pady=(top, 0))
        self._label(f, title.upper(), self.f_label, C["muted"]).pack(anchor="w", pady=(0, 7))
        return f

    def _check(self, parent, text, var, command=None):
        return tk.Checkbutton(parent, text=text, variable=var, command=command,
                              font=self.f_ui, fg=C["text"], bg=C["surface"],
                              selectcolor=C["field"], activebackground=C["surface"],
                              activeforeground=C["text"], highlightthickness=0, bd=0,
                              anchor="w", cursor="hand2", takefocus=0)

    # ------------------------------------------------------------ layout
    def _build(self):
        self.columnconfigure(2, weight=1)
        self.rowconfigure(0, weight=1)
        self._build_sidebar()
        tk.Frame(self, bg=C["border"], width=1).grid(row=0, column=1, sticky="ns")
        self._build_main()

    def _build_sidebar(self):
        sb = tk.Frame(self, bg=C["surface"], width=336)
        sb.grid(row=0, column=0, sticky="ns")
        sb.pack_propagate(False)

        head = tk.Frame(sb, bg=C["surface"])
        head.pack(fill="x", padx=18, pady=(18, 4))
        self._label(head, "Little-Sandbox", self.f_title).pack(anchor="w")
        self._label(head, "Active Threat Interceptor v2", self.f_small, C["muted"]).pack(anchor="w")

        # Run / Stop are packed first so they always keep their space at the bottom.
        bottom = tk.Frame(sb, bg=C["surface"])
        bottom.pack(side="bottom", fill="x", padx=18, pady=(10, 16))
        btns = tk.Frame(bottom, bg=C["surface"])
        btns.pack(fill="x")
        self.btn_run = Flat(btns, "Run analysis", self.run, "primary", self.f_bold, pady=8)
        self.btn_run.pack(side="left", fill="x", expand=True)
        self.btn_stop = Flat(btns, "Stop", self.stop, "danger", self.f_bold, pady=8, padx=18)
        self.btn_stop.pack(side="left", padx=(8, 0))
        self.btn_stop.enable(False)
        self._label(bottom, "Ctrl+Enter to run  ·  Esc to stop", self.f_small,
                    C["faint"]).pack(anchor="w", pady=(8, 0))

        sec = self._section(sb, "Target", top=14)
        self._field(sec, "Script to analyze", self.v_target, self._pick_target)
        self._field(sec, "Arguments (optional)", self.v_args)

        sec = self._section(sb, "Sandbox")
        seg = tk.Frame(sec, bg=C["field"], highlightthickness=1, highlightbackground=C["border"])
        seg.pack(fill="x")
        self.seg_btns = {}
        for val, text in (("observe", "Observe"), ("strict", "Strict")):
            rb = tk.Radiobutton(seg, text=text, value=val, variable=self.v_mode,
                                indicatoron=0, bd=0, relief="flat", font=self.f_ui,
                                bg=C["field"], fg=C["muted"], selectcolor=C["accent_dim"],
                                activebackground=C["raised"], activeforeground=C["text"],
                                highlightthickness=0, padx=10, pady=6, cursor="hand2",
                                takefocus=0, command=self._mode_hint)
            rb.pack(side="left", fill="x", expand=True)
            self.seg_btns[val] = rb
        self.lbl_hint = self._label(sec, "", self.f_small, C["muted"], justify="left", wraplength=296)
        self.lbl_hint.pack(anchor="w", pady=(7, 10))

        row = tk.Frame(sec, bg=C["surface"])
        row.pack(fill="x")
        self._label(row, "Time limit", self.f_ui, C["muted"]).pack(side="left")
        self._entry(row, self.v_timeout, width=6).pack(side="left", padx=8, ipady=4)
        self._label(row, "seconds", self.f_small, C["muted"]).pack(side="left")

        self._check(sec, "Share host network", self.v_net, self._net_warn).pack(anchor="w", pady=(10, 0))
        self.lbl_net = self._label(sec, "Off by default. The jail has no network.", self.f_small, C["faint"])
        self.lbl_net.pack(anchor="w", padx=(22, 0))

        sec = self._section(sb, "AI triage")
        self._check(sec, "Ask Gemini for a second opinion", self.v_analyze,
                    self._sync_analyst).pack(anchor="w")
        self._label(sec, "Advisory only. It can raise the verdict, never lower it.",
                    self.f_small, C["faint"], justify="left", wraplength=296).pack(
            anchor="w", padx=(22, 0), pady=(0, 8))
        self.e_key = self._field(sec, "API key", self.v_key, show="•")
        self.e_model = self._field(sec, "Model (blank = default)", self.v_model)

        self.adv_open = False
        self.btn_adv = Flat(sb, "Advanced  +", self._toggle_adv, "ghost", self.f_small,
                            bg=C["surface"], pady=4, padx=0, anchor="w")
        self.btn_adv.pack(fill="x", padx=18, pady=(10, 0))
        self.adv = tk.Frame(sb, bg=C["surface"])
        self._field(self.adv, "Interceptor script", self.v_icp, self._pick_icp)
        self._field(self.adv, "Write JSONL log to", self.v_log, self._pick_log)
        row = tk.Frame(self.adv, bg=C["surface"])
        row.pack(fill="x")
        self._label(row, "Max events", self.f_ui, C["muted"]).pack(side="left")
        self._entry(row, self.v_maxev, width=9).pack(side="left", padx=8, ipady=4)

    def _build_main(self):
        pad = 18
        main = tk.Frame(self, bg=C["bg"])
        main.grid(row=0, column=2, sticky="nsew")
        main.columnconfigure(0, weight=1)
        main.rowconfigure(2, weight=1)

        # verdict card
        card = tk.Frame(main, bg=C["surface"], highlightthickness=1, highlightbackground=C["border"])
        card.grid(row=0, column=0, sticky="ew", padx=pad, pady=(pad, 12))
        card.columnconfigure(2, weight=1)
        self.bar = tk.Frame(card, bg=C["border"], width=4)
        self.bar.grid(row=0, column=0, sticky="ns")

        left = tk.Frame(card, bg=C["surface"])
        left.grid(row=0, column=1, sticky="w", padx=(16, 28), pady=12)
        self._label(left, "VERDICT", self.f_label, C["muted"]).pack(anchor="w")
        self.lbl_verdict = tk.Label(left, textvariable=self.v_verdict, font=self.f_big,
                                    bg=C["surface"], fg=C["faint"], anchor="w", width=11)
        self.lbl_verdict.pack(anchor="w")
        tk.Label(left, textvariable=self.v_sub, font=self.f_small, bg=C["surface"],
                 fg=C["muted"], anchor="w", justify="left", wraplength=260).pack(anchor="w")

        mid = tk.Frame(card, bg=C["surface"])
        mid.grid(row=0, column=2, sticky="ew", padx=(0, 28))
        tk.Label(mid, textvariable=self.v_time, font=self.f_mono_s, bg=C["surface"],
                 fg=C["muted"], anchor="w").pack(fill="x", pady=(0, 6))
        self.prog = ttk.Progressbar(mid, style="Thin.Horizontal.TProgressbar",
                                    mode="determinate", maximum=100)
        self.prog.pack(fill="x")

        stats = tk.Frame(card, bg=C["surface"])
        stats.grid(row=0, column=3, padx=(0, 20), pady=12)
        self.lbl_n = {}
        for key, cap, col in (("INFO", "info", "muted"), ("WARN", "warnings", "warn"),
                              ("BLOCK", "blocked", "bad")):
            t = tk.Frame(stats, bg=C["surface"])
            t.pack(side="left", padx=12)
            n = tk.Label(t, text="0", font=self.f_num, bg=C["surface"], fg=C[col])
            n.pack()
            self._label(t, cap, self.f_small, C["muted"]).pack()
            self.lbl_n[key] = n

        # toolbar
        tb = tk.Frame(main, bg=C["bg"])
        tb.grid(row=1, column=0, sticky="ew", padx=pad, pady=(0, 8))
        self.chips = {}
        for key, text, col in (("INFO", "Info", "muted"), ("WARN", "Warnings", "warn"),
                               ("BLOCK", "Blocked", "bad"), ("target", "Script output", "text")):
            cb = tk.Checkbutton(tb, text=text, variable=self.show[key], indicatoron=0,
                                command=self._apply_filter, bd=0, relief="flat",
                                font=self.f_small, padx=11, pady=4, bg=C["bg"],
                                fg=C["faint"], selectcolor=C["raised"],
                                activebackground=C["raised"], activeforeground=C["text"],
                                highlightthickness=1, highlightbackground=C["border"],
                                highlightcolor=C["border"], cursor="hand2", takefocus=0)
            cb.pack(side="left", padx=(0, 6))
            self.chips[key] = (cb, col)
        Flat(tb, "Save log", self.save, "ghost", self.f_small, pady=4).pack(side="right")
        Flat(tb, "Clear", self.clear_log, "ghost", self.f_small, pady=4).pack(side="right")

        # log + lower panes
        paned = tk.PanedWindow(main, orient="vertical", bg=C["bg"], bd=0,
                               sashwidth=8, sashrelief="flat", opaqueresize=True)
        paned.grid(row=2, column=0, sticky="nsew", padx=pad, pady=(0, 6))

        logf = tk.Frame(paned, bg=C["panel"], highlightthickness=1, highlightbackground=C["border"])
        logf.rowconfigure(0, weight=1)
        logf.columnconfigure(0, weight=1)
        self.text = tk.Text(logf, bg=C["panel"], fg=C["text"], font=self.f_mono, wrap="none",
                            bd=0, relief="flat", highlightthickness=0, padx=12, pady=10,
                            spacing1=2, state="disabled", cursor="arrow",
                            selectbackground=C["select"], selectforeground=C["text"],
                            insertwidth=0)
        ys = ttk.Scrollbar(logf, orient="vertical", style="Dark.Vertical.TScrollbar",
                           command=self.text.yview)
        xs = ttk.Scrollbar(logf, orient="horizontal", style="Dark.Horizontal.TScrollbar",
                           command=self.text.xview)
        self.text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.text.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        self.text.bind("<Button-1>", lambda e: self.text.focus_set())
        self.text.tag_configure("ts", foreground=C["faint"])
        self.text.tag_configure("b", font=self.f_mono_b)
        for name in ("text", "muted", "faint", "ok", "warn", "bad", "accent"):
            self.text.tag_configure(f"c_{name}", foreground=C[name])
        for k in ("INFO", "WARN", "BLOCK", "target"):
            self.text.tag_configure(f"sev_{k}")
        self.empty = tk.Label(logf, text="No run yet\nPick a script and press Run analysis.",
                              font=self.f_ui, fg=C["faint"], bg=C["panel"], justify="center")
        self.empty.place(relx=0.5, rely=0.45, anchor="center")
        paned.add(logf, minsize=180, stretch="always")

        low = tk.Frame(paned, bg=C["bg"])
        low.columnconfigure(0, weight=1, uniform="low")
        low.columnconfigure(1, weight=1, uniform="low")
        low.rowconfigure(1, weight=1)

        h = tk.Frame(low, bg=C["bg"])
        h.grid(row=0, column=0, sticky="ew", pady=(4, 6), padx=(0, 6))
        self.lbl_ioc = self._label(h, "INDICATORS", self.f_label, C["muted"], bg=C["bg"])
        self.lbl_ioc.pack(side="left")
        Flat(h, "Copy", self.copy_iocs, "ghost", self.f_small, padx=8, pady=0).pack(side="right")
        box = tk.Frame(low, bg=C["panel"], highlightthickness=1, highlightbackground=C["border"])
        box.grid(row=1, column=0, sticky="nsew", padx=(0, 6))
        box.rowconfigure(0, weight=1)
        box.columnconfigure(0, weight=1)
        self.ioc = tk.Listbox(box, bg=C["panel"], fg=C["warn"], font=self.f_mono_s, bd=0,
                              highlightthickness=0, selectbackground=C["select"],
                              selectforeground=C["text"], activestyle="none",
                              selectmode="extended", height=6)
        iy = ttk.Scrollbar(box, orient="vertical", style="Dark.Vertical.TScrollbar",
                           command=self.ioc.yview)
        self.ioc.configure(yscrollcommand=iy.set)
        self.ioc.grid(row=0, column=0, sticky="nsew", padx=(8, 0), pady=6)
        iy.grid(row=0, column=1, sticky="ns")

        self._label(low, "ANALYST NOTES", self.f_label, C["muted"], bg=C["bg"]).grid(
            row=0, column=1, sticky="w", pady=(4, 6), padx=(6, 0))
        nbox = tk.Frame(low, bg=C["panel"], highlightthickness=1, highlightbackground=C["border"])
        nbox.grid(row=1, column=1, sticky="nsew", padx=(6, 0))
        nbox.rowconfigure(0, weight=1)
        nbox.columnconfigure(0, weight=1)
        self.notes = tk.Text(nbox, bg=C["panel"], fg=C["text"], font=self.f_small, wrap="word",
                             bd=0, highlightthickness=0, padx=10, pady=8, spacing1=2,
                             spacing3=4, state="disabled", cursor="arrow", height=6,
                             selectbackground=C["select"], insertwidth=0)
        ny = ttk.Scrollbar(nbox, orient="vertical", style="Dark.Vertical.TScrollbar",
                           command=self.notes.yview)
        self.notes.configure(yscrollcommand=ny.set)
        self.notes.grid(row=0, column=0, sticky="nsew")
        ny.grid(row=0, column=1, sticky="ns")
        self.notes.bind("<Button-1>", lambda e: self.notes.focus_set())
        for name in ("text", "muted", "faint", "ok", "warn", "bad", "accent"):
            self.notes.tag_configure(f"c_{name}", foreground=C[name])
        paned.add(low, minsize=110, height=190, stretch="never")

        tk.Label(main, textvariable=self.v_status, font=self.f_small, fg=C["muted"],
                 bg=C["bg"], anchor="w").grid(row=3, column=0, sticky="ew", padx=pad, pady=(2, 12))

    # ------------------------------------------------------------ small handlers
    def _toggle_adv(self):
        self.adv_open = not self.adv_open
        if self.adv_open:
            self.adv.pack(fill="x", padx=18, pady=(8, 0), after=self.btn_adv)
            self.btn_adv.configure(text="Advanced  –")
        else:
            self.adv.pack_forget()
            self.btn_adv.configure(text="Advanced  +")

    def _mode_hint(self):
        mode = self.v_mode.get()
        self.lbl_hint.configure(text=MODE_HINT[mode])
        for val, rb in self.seg_btns.items():
            rb.configure(fg=C["text"] if val == mode else C["muted"])

    def _sync_analyst(self):
        st = "normal" if self.v_analyze.get() else "disabled"
        self.e_key.configure(state=st)
        self.e_model.configure(state=st)

    def _net_warn(self):
        if self.v_net.get():
            if not messagebox.askyesno(
                    "Share host network?",
                    "This gives the untrusted script access to your real network.\n"
                    "Only enable it if you understand the risk. Continue?"):
                self.v_net.set(False)
        if self.v_net.get():
            self.lbl_net.configure(text="On. The script can reach your network.", fg=C["warn"])
        else:
            self.lbl_net.configure(text="Off by default. The jail has no network.", fg=C["faint"])

    def _apply_filter(self):
        for k, var in self.show.items():
            self.text.tag_configure(f"sev_{k}", elide=not var.get())
            cb, col = self.chips[k]
            cb.configure(fg=C[col] if var.get() else C["faint"])

    def _pick_target(self):
        p = filedialog.askopenfilename(title="Script to analyze",
                                       filetypes=[("Python", "*.py"), ("All files", "*")])
        if p:
            self.v_target.set(p)

    def _pick_icp(self):
        p = filedialog.askopenfilename(title="Interceptor script", initialdir=HERE,
                                       filetypes=[("Python", "*.py"), ("All files", "*")])
        if p:
            self.v_icp.set(p)

    def _pick_log(self):
        p = filedialog.asksaveasfilename(defaultextension=".jsonl",
                                         filetypes=[("JSON lines", "*.jsonl"), ("All files", "*")])
        if p:
            self.v_log.set(p)

    # ------------------------------------------------------------ verdict card
    def _show_state(self, word, color, sub=""):
        self.v_verdict.set(word)
        self.v_sub.set(sub)
        self.lbl_verdict.configure(fg=C[color])
        self.bar.configure(bg=C[color] if color != "faint" else C["border"])

    def _idle_state(self):
        self._show_state("No run yet", "faint", "Select a script and press Run analysis.")
        self.v_time.set("—")
        self.prog["value"] = 0

    def _set_verdict(self, word, sub=""):
        col = VERDICT_COLOR.get(word.upper(), "muted")
        self._show_state(word.capitalize(), col, sub)

    # ------------------------------------------------------------ run control
    def run(self):
        if self.proc:
            return
        icp = self.v_icp.get().strip()
        target = self.v_target.get().strip()
        if not os.path.isfile(target):
            return messagebox.showerror("No script", "Pick the script you want to analyze.")
        if not os.path.isfile(icp):
            if not self.adv_open:
                self._toggle_adv()
            return messagebox.showerror("Interceptor not found",
                                        "Set the path to interceptor.py under Advanced.")
        if not os.path.realpath(sys.executable).startswith("/usr/"):
            return messagebox.showerror(
                "Wrong Python",
                "The interceptor only runs under the system Python (/usr/bin/python3), "
                "not a venv or pyenv.\n\nThis GUI is running under:\n" + sys.executable)
        if not shutil.which("bwrap"):
            return messagebox.showerror("bubblewrap missing",
                                        "Install it first:\n\n    sudo apt install bubblewrap")
        try:
            timeout = float(self.v_timeout.get())
            maxev = int(self.v_maxev.get())
            args = shlex.split(self.v_args.get())
            if timeout <= 0 or maxev <= 0:
                raise ValueError("time limit and max events must be positive")
        except ValueError as e:
            return messagebox.showerror("Invalid input", str(e))
        analyze = self.v_analyze.get()
        key = self.v_key.get().strip()
        if analyze and not key:
            return messagebox.showerror("API key needed",
                                        "AI triage needs a GEMINI_API_KEY.")

        cmd = [sys.executable, icp, "--timeout", str(timeout), "--max-events", str(maxev)]
        if self.v_mode.get() == "strict":
            cmd.append("--strict")
        if self.v_net.get():
            cmd.append("--net")
        if analyze:
            cmd.append("--analyze")
        if self.v_log.get().strip():
            cmd += ["--log", self.v_log.get().strip()]
        cmd.append(target)
        if args:
            cmd += ["--"] + args

        env = os.environ.copy()
        env["PYTHONUNBUFFERED"] = "1"
        if key:
            env["GEMINI_API_KEY"] = key
        if self.v_model.get().strip():
            env["ATI_MODEL"] = self.v_model.get().strip()

        self.clear_log(force=True)
        try:
            self.proc = subprocess.Popen(
                cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, env=env, start_new_session=True)
        except OSError as e:
            self.proc = None
            return messagebox.showerror("Could not start", str(e))

        self.stopped = False
        self.timeout_s = timeout
        self.t0 = time.monotonic()
        mode = self.v_mode.get()
        net = "on" if self.v_net.get() else "off"
        self._show_state("Running", "accent",
                         f"{mode.capitalize()} mode  ·  network {net}  ·  {timeout:g} s limit")
        self.v_status.set(f"Analyzing {os.path.basename(target)}")
        self.btn_run.enable(False)
        self.btn_stop.enable(True)
        threading.Thread(target=self._read, args=(self.proc,), daemon=True).start()

    def _read(self, proc):
        for raw in iter(proc.stdout.readline, b""):
            self.q.put(("line", raw.decode("utf-8", "replace").rstrip("\n")))
        self.q.put(("done", proc.wait()))

    def stop(self):
        if self.proc and self.proc.poll() is None:
            self.stopped = True
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)   # bwrap uses --die-with-parent
            except ProcessLookupError:
                pass

    def _close(self):
        self.stop()
        self.destroy()

    def _pump(self):
        try:
            for _ in range(500):
                kind, val = self.q.get_nowait()
                if kind == "line":
                    self._line(val)
                else:
                    self._done(val)
        except queue.Empty:
            pass
        self.after(40, self._pump)

    def _tick(self):
        if self.proc and self.t0:
            e = time.monotonic() - self.t0
            self.v_time.set(f"{e:5.1f} s  of  {self.timeout_s:g} s limit")
            self.prog["value"] = min(100.0, e / self.timeout_s * 100.0)
        self.after(100, self._tick)

    def _done(self, rc):
        elapsed = time.monotonic() - self.t0 if self.t0 else 0.0
        self.proc = None
        self.btn_run.enable(True)
        self.btn_stop.enable(False)
        self.v_time.set(f"finished in {elapsed:.1f} s")
        self.prog["value"] = 100 if rc in (0, 2) else self.prog["value"]
        if self.v_verdict.get() == "Running" or self.stopped:
            if self.stopped:
                self._show_state("Stopped", "muted", "Run was stopped before a verdict.")
                self.v_status.set("Stopped by you")
                return
            tail = " ".join(self.err_tail[-3:]).strip()
            self._show_state("Run failed", "bad", tail[:160] or f"Interceptor exited with code {rc}.")
        meaning = {0: "benign", 2: "flagged"}.get(rc, "error")
        self.v_status.set(f"Finished  ·  exit code {rc} ({meaning})")

    # ------------------------------------------------------------ output
    def _colors(self, tag, msg):
        if tag == "INFO":
            return "muted", "text"
        if tag in ("WARN", "IOC"):
            return "warn", "warn"
        if tag in ("BLOCK", "KILLED", "SPOOF?"):
            return "bad", "bad"
        if tag in ("START", "SUMMARY"):
            return "ok", "text"
        if tag in ("RULES-VERD", "FINAL", "AI-VERDICT"):
            col = VERDICT_COLOR.get(msg.split()[0].upper() if msg.split() else "", "muted")
            return col, col
        if tag == "AI":
            return "accent", "text"
        return "muted", "text"

    def _line(self, raw):
        text = ANSI.sub("", raw)
        m = TS_LINE.match(text)
        if m:
            ts, tag, msg = m.groups()
            self._on_event(tag, msg)
            tcol, mcol = self._colors(tag, msg)
            msg_tags = (f"c_{mcol}",) + (("b",) if tag in ("FINAL", "AI-VERDICT", "KILLED") else ())
            parts = [(f"{float(ts):7.3f}  ", ("ts",)),
                     (f"{tag:<10} ", (f"c_{tcol}",)),
                     (msg, msg_tags)]
            sev = tag if tag in ("INFO", "WARN", "BLOCK") else None
            if sev:
                self.counts[sev] += 1
                self.lbl_n[sev].configure(text=str(self.counts[sev]))
        else:
            t = TARGET_LINE.match(text)
            if t:
                stream, body = t.groups()
                parts = [(" " * 9, ()),
                         (f"{stream:<10} ", ("c_faint",)),
                         (body, ("c_bad" if stream == "stderr" else "c_text",))]
                sev = "target"
            else:
                if text.strip():
                    self.err_tail = (self.err_tail + [text.strip()])[-6:]
                parts = [(text, ("c_muted",))]
                sev = None
        self._emit(parts, sev)

    def _emit(self, parts, sev):
        if self.empty_shown:
            self.empty.place_forget()
            self.empty_shown = False
        at_end = self.text.yview()[1] >= 0.999
        self.text.configure(state="normal")
        for s, tags in parts:
            tags = tags + ((f"sev_{sev}",) if sev else ())
            self.text.insert("end", s, tags)
        self.text.insert("end", "\n")
        self.text.configure(state="disabled")
        if at_end:
            self.text.see("end")

    def _on_event(self, tag, msg):
        if tag == "IOC":
            self.ioc.insert("end", msg.strip())
            self.lbl_ioc.configure(text=f"INDICATORS  ({self.ioc.size()})")
        elif tag == "RULES-VERD" and msg.split():
            sub = "Rules verdict"
            if self.v_analyze.get():
                sub += "  ·  waiting for the AI analyst"
            self._set_verdict(msg.split()[0], sub)
        elif tag == "FINAL" and msg.split():
            inner = re.search(r"\((.*)\)", msg)
            sub = inner.group(1).replace("=", ": ").replace(", ", "  ·  ") if inner else ""
            self._set_verdict(msg.split()[0], sub)
        elif tag == "AI":
            if not msg.startswith(("---", "===")):
                self._note(msg, "text")
        elif tag == "AI-VERDICT":
            col = self._colors(tag, msg)[0]
            self._note("Verdict: " + msg, col)

    def _note(self, text, color):
        self.notes.configure(state="normal")
        if self.notes_empty:
            self.notes.delete("1.0", "end")
            self.notes_empty = False
        self.notes.insert("end", text + "\n", (f"c_{color}",))
        self.notes.configure(state="disabled")
        self.notes.see("end")

    # ------------------------------------------------------------ actions
    def clear_log(self, force=False):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")
        self.ioc.delete(0, "end")
        self.lbl_ioc.configure(text="INDICATORS")
        self.notes.configure(state="normal")
        self.notes.delete("1.0", "end")
        hint = ("Turn on AI triage in the sidebar for a second opinion."
                if not self.v_analyze.get() else "Waiting for the run to finish.")
        self.notes.insert("end", hint, ("c_faint",))
        self.notes.configure(state="disabled")
        self.notes_empty = True
        self.counts = {"INFO": 0, "WARN": 0, "BLOCK": 0}
        for k, lbl in self.lbl_n.items():
            lbl.configure(text="0")
        self.err_tail = []
        if not self.empty_shown:
            self.empty.place(relx=0.5, rely=0.45, anchor="center")
            self.empty_shown = True
        if not self.proc and not force:
            self._idle_state()
            self.v_status.set("Ready")

    def copy_iocs(self):
        sel = self.ioc.curselection()
        items = [self.ioc.get(i) for i in (sel or range(self.ioc.size()))]
        if not items:
            return
        self.clipboard_clear()
        self.clipboard_append("\n".join(items))
        self.v_status.set(f"Copied {len(items)} indicator{'s' if len(items) != 1 else ''}")

    def save(self):
        p = filedialog.asksaveasfilename(defaultextension=".txt",
                                         filetypes=[("Text", "*.txt"), ("All files", "*")])
        if p:
            with open(p, "w") as f:
                f.write(self.text.get("1.0", "end"))
            self.v_status.set(f"Log saved to {p}")


if __name__ == "__main__":
    if not sys.platform.startswith("linux"):
        sys.exit("The interceptor is Linux only.")
    App().mainloop()