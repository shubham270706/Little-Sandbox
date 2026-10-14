#!/usr/bin/env python3
"""
Active Threat Interceptor - Tkinter front-end.

Put this file next to interceptor.py (or interceptor_v2.py) and run:

    /usr/bin/python3 interceptor_gui.py

It launches the interceptor as a subprocess, so the sandbox logic stays
untouched. Requires the system Python under /usr (the interceptor refuses
venv/pyenv interpreters) with tkinter installed: sudo apt install python3-tk
"""
import os
import queue
import re
import shlex
import signal
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

HERE = os.path.dirname(os.path.realpath(__file__))
ANSI = re.compile(r"\x1b\[(\d+)m")
LINE = re.compile(r"^\[\s*[\d.]+\]\s+(\S+)")

BG, PANEL, FG = "#1e1f26", "#262833", "#d8dae5"
COLORS = {"red": "#ff6b6b", "yellow": "#f5c542", "green": "#5fd38d",
          "cyan": "#5cc8ff", "dim": "#7d8190", "magenta": "#d58cff", "plain": FG}
CODE_TAG = {"91": "red", "93": "yellow", "92": "green", "96": "cyan",
            "2": "dim", "95": "magenta"}
VERDICT_COLOR = {"BENIGN": COLORS["green"], "SUSPICIOUS": COLORS["yellow"],
                 "BLOCKED": COLORS["red"], "MALICIOUS": COLORS["red"]}


def find_interceptor():
    for name in ("interceptor.py", "interceptor_v2.py"):
        p = os.path.join(HERE, name)
        if os.path.isfile(p):
            return p
    return ""


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Active Threat Interceptor")
        self.geometry("1100x760")
        self.minsize(900, 600)
        self.configure(bg=BG)

        self.q = queue.Queue()
        self.proc = None
        self.counts = {"INFO": 0, "WARN": 0, "BLOCK": 0}
        self.iocs = []

        self._style()
        self._vars()
        self._build()
        self.after(50, self._pump)
        self.protocol("WM_DELETE_WINDOW", self._close)

    # ---------- setup ----------
    def _style(self):
        s = ttk.Style(self)
        s.theme_use("clam")
        s.configure(".", background=BG, foreground=FG, fieldbackground=PANEL)
        s.configure("TFrame", background=BG)
        s.configure("Panel.TLabelframe", background=BG, foreground=FG)
        s.configure("Panel.TLabelframe.Label", background=BG, foreground=COLORS["cyan"])
        s.configure("TLabel", background=BG, foreground=FG)
        s.configure("TCheckbutton", background=BG, foreground=FG)
        s.configure("TEntry", fieldbackground=PANEL, foreground=FG)
        s.configure("TButton", background=PANEL, foreground=FG, padding=6)
        s.map("TButton", background=[("active", "#34374a")])
        s.configure("Run.TButton", background="#2e7d4f", foreground="white")
        s.map("Run.TButton", background=[("active", "#37965e"), ("disabled", "#3a3d4d")])
        s.configure("Stop.TButton", background="#a33a3a", foreground="white")
        s.map("Stop.TButton", background=[("active", "#c24848"), ("disabled", "#3a3d4d")])

    def _vars(self):
        self.v_icp = tk.StringVar(value=find_interceptor())
        self.v_target = tk.StringVar()
        self.v_args = tk.StringVar()
        self.v_timeout = tk.StringVar(value="10")
        self.v_maxev = tk.StringVar(value="20000")
        self.v_log = tk.StringVar()
        self.v_key = tk.StringVar(value=os.environ.get("GEMINI_API_KEY", ""))
        self.v_model = tk.StringVar(value=os.environ.get("ATI_MODEL", ""))
        self.v_strict = tk.BooleanVar()
        self.v_net = tk.BooleanVar()
        self.v_analyze = tk.BooleanVar()
        self.v_status = tk.StringVar(value="Idle")
        self.v_verdict = tk.StringVar(value="-")
        self.show = {k: tk.BooleanVar(value=True)
                     for k in ("INFO", "WARN", "BLOCK", "target")}

    def _row(self, parent, r, label, var, browse=None, show=None):
        ttk.Label(parent, text=label).grid(row=r, column=0, sticky="w", padx=(8, 6), pady=3)
        e = ttk.Entry(parent, textvariable=var, show=show or "")
        e.grid(row=r, column=1, sticky="ew", pady=3)
        if browse:
            ttk.Button(parent, text="Browse...", command=browse).grid(
                row=r, column=2, padx=8, pady=3)
        return e

    def _build(self):
        top = ttk.LabelFrame(self, text=" Target ", style="Panel.TLabelframe")
        top.pack(fill="x", padx=10, pady=(10, 4))
        top.columnconfigure(1, weight=1)
        self._row(top, 0, "Interceptor", self.v_icp, self._pick_icp)
        self._row(top, 1, "Script to analyze", self.v_target, self._pick_target)
        self._row(top, 2, "Script args", self.v_args)

        opt = ttk.LabelFrame(self, text=" Options ", style="Panel.TLabelframe")
        opt.pack(fill="x", padx=10, pady=4)
        opt.columnconfigure(1, weight=1)
        flags = ttk.Frame(opt)
        flags.grid(row=0, column=0, columnspan=3, sticky="w", padx=8, pady=3)
        ttk.Checkbutton(flags, text="Strict (block dangerous calls)",
                        variable=self.v_strict).pack(side="left", padx=(0, 16))
        ttk.Checkbutton(flags, text="Share host network (--net, risky)",
                        variable=self.v_net, command=self._net_warn).pack(side="left", padx=(0, 16))
        ttk.Checkbutton(flags, text="AI analyst (Gemini API)",
                        variable=self.v_analyze).pack(side="left")
        nums = ttk.Frame(opt)
        nums.grid(row=1, column=0, columnspan=3, sticky="w", padx=8, pady=3)
        ttk.Label(nums, text="Timeout (s)").pack(side="left")
        ttk.Entry(nums, textvariable=self.v_timeout, width=7).pack(side="left", padx=(6, 18))
        ttk.Label(nums, text="Max events").pack(side="left")
        ttk.Entry(nums, textvariable=self.v_maxev, width=9).pack(side="left", padx=6)
        self._row(opt, 2, "JSONL log (optional)", self.v_log, self._pick_log)
        self._row(opt, 3, "GEMINI_API_KEY", self.v_key, show="*")
        self._row(opt, 4, "Model (ATI_MODEL)", self.v_model)

        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=10, pady=6)
        self.btn_run = ttk.Button(bar, text="Run", style="Run.TButton", command=self.run)
        self.btn_run.pack(side="left")
        self.btn_stop = ttk.Button(bar, text="Stop", style="Stop.TButton",
                                   command=self.stop, state="disabled")
        self.btn_stop.pack(side="left", padx=6)
        ttk.Button(bar, text="Clear", command=self.clear).pack(side="left")
        ttk.Button(bar, text="Save output...", command=self.save).pack(side="left", padx=6)
        ttk.Label(bar, text="Verdict:").pack(side="right", padx=(0, 4))
        self.lbl_verdict = tk.Label(bar, textvariable=self.v_verdict, bg=BG, fg=COLORS["dim"],
                                    font=("TkDefaultFont", 13, "bold"), width=12, anchor="w")
        self.lbl_verdict.pack(side="right")
        self.lbl_counts = tk.Label(bar, text=self._counts_text(), bg=BG, fg=FG)
        self.lbl_counts.pack(side="right", padx=16)

        flt = ttk.Frame(self)
        flt.pack(fill="x", padx=10)
        ttk.Label(flt, text="Show:").pack(side="left")
        for key, label in (("INFO", "INFO"), ("WARN", "WARN"),
                           ("BLOCK", "BLOCK"), ("target", "Script stdout/stderr")):
            ttk.Checkbutton(flt, text=label, variable=self.show[key],
                            command=self._apply_filter).pack(side="left", padx=8)

        body = ttk.PanedWindow(self, orient="horizontal")
        body.pack(fill="both", expand=True, padx=10, pady=6)

        left = ttk.Frame(body)
        self.text = tk.Text(left, bg=PANEL, fg=FG, insertbackground=FG, wrap="none",
                            font=("Monospace", 10), relief="flat", state="disabled")
        ys = ttk.Scrollbar(left, command=self.text.yview)
        xs = ttk.Scrollbar(left, orient="horizontal", command=self.text.xview)
        self.text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        ys.pack(side="right", fill="y")
        xs.pack(side="bottom", fill="x")
        self.text.pack(fill="both", expand=True)
        for name, col in COLORS.items():
            self.text.tag_configure(name, foreground=col)
        for k in ("INFO", "WARN", "BLOCK", "target"):
            self.text.tag_configure("sev_" + k)
        body.add(left, weight=4)

        right = ttk.LabelFrame(body, text=" Indicators of compromise ",
                               style="Panel.TLabelframe")
        self.ioc = tk.Listbox(right, bg=PANEL, fg=COLORS["yellow"], relief="flat",
                              font=("Monospace", 9), selectbackground="#3a3d4d")
        self.ioc.pack(fill="both", expand=True, padx=4, pady=4)
        body.add(right, weight=1)

        ttk.Label(self, textvariable=self.v_status, anchor="w").pack(
            fill="x", padx=10, pady=(0, 8))

    # ---------- pickers ----------
    def _pick_icp(self):
        p = filedialog.askopenfilename(title="interceptor.py", initialdir=HERE,
                                       filetypes=[("Python", "*.py"), ("All", "*")])
        if p:
            self.v_icp.set(p)

    def _pick_target(self):
        p = filedialog.askopenfilename(title="Script to analyze",
                                       filetypes=[("Python", "*.py"), ("All", "*")])
        if p:
            self.v_target.set(p)

    def _pick_log(self):
        p = filedialog.asksaveasfilename(defaultextension=".jsonl",
                                         filetypes=[("JSONL", "*.jsonl"), ("All", "*")])
        if p:
            self.v_log.set(p)

    def _net_warn(self):
        if self.v_net.get() and not messagebox.askyesno(
                "Share network?",
                "--net gives the untrusted script access to your real network.\n"
                "Only enable this if you understand the risk. Continue?"):
            self.v_net.set(False)

    # ---------- run control ----------
    def run(self):
        icp, target = self.v_icp.get().strip(), self.v_target.get().strip()
        if not os.path.isfile(icp):
            return messagebox.showerror("Missing", "Select the interceptor script.")
        if not os.path.isfile(target):
            return messagebox.showerror("Missing", "Select a script to analyze.")
        try:
            timeout = float(self.v_timeout.get())
            maxev = int(self.v_maxev.get())
            args = shlex.split(self.v_args.get())
        except ValueError as e:
            return messagebox.showerror("Invalid input", str(e))
        if self.v_analyze.get() and not self.v_key.get().strip():
            return messagebox.showerror("Missing", "AI analyst needs a GEMINI_API_KEY.")

        cmd = [sys.executable, icp, "--timeout", str(timeout), "--max-events", str(maxev)]
        if self.v_strict.get():
            cmd.append("--strict")
        if self.v_net.get():
            cmd.append("--net")
        if self.v_analyze.get():
            cmd.append("--analyze")
        if self.v_log.get().strip():
            cmd += ["--log", self.v_log.get().strip()]
        cmd.append(target)
        if args:
            cmd += ["--"] + args

        env = os.environ.copy()
        if self.v_key.get().strip():
            env["GEMINI_API_KEY"] = self.v_key.get().strip()
        if self.v_model.get().strip():
            env["ATI_MODEL"] = self.v_model.get().strip()

        self.clear()
        self.v_verdict.set("running...")
        self.lbl_verdict.configure(fg=COLORS["cyan"])
        try:
            self.proc = subprocess.Popen(
                cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, env=env, start_new_session=True)
        except OSError as e:
            return messagebox.showerror("Launch failed", str(e))
        self.btn_run.configure(state="disabled")
        self.btn_stop.configure(state="normal")
        self.v_status.set("Running: " + " ".join(shlex.quote(c) for c in cmd[1:]))
        threading.Thread(target=self._read, args=(self.proc,), daemon=True).start()

    def _read(self, proc):
        for raw in iter(proc.stdout.readline, b""):
            self.q.put(("line", raw.decode("utf-8", "replace").rstrip("\n")))
        self.q.put(("done", proc.wait()))

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGKILL)  # bwrap uses --die-with-parent
            except ProcessLookupError:
                pass
            self.v_status.set("Stopped by user")

    def _close(self):
        self.stop()
        self.destroy()

    # ---------- output handling ----------
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
        self.after(50, self._pump)

    def _line(self, raw):
        m = ANSI.search(raw)
        color = CODE_TAG.get(m.group(1), "plain") if m else "plain"
        text = ANSI.sub("", raw)
        lm = LINE.match(text)
        tag = lm.group(1) if lm else ""
        if "| stdout:" in text[:20] or "| stderr:" in text[:20]:
            sev = "target"
        elif tag in ("INFO", "WARN", "BLOCK"):
            sev = tag
            self.counts[tag] += 1
            self.lbl_counts.configure(text=self._counts_text())
        else:
            sev = None
        if tag == "IOC":
            self.ioc.insert("end", text.split("IOC", 1)[1].strip())
        if tag == "FINAL":
            self._set_verdict(text.split("FINAL", 1)[1].split()[0])
        elif tag == "RULES-VERD" and not self.v_analyze.get():
            self._set_verdict(text.split("RULES-VERD", 1)[1].split()[0])

        tags = (color,) + (("sev_" + sev,) if sev else ())
        at_end = self.text.yview()[1] >= 0.999
        self.text.configure(state="normal")
        self.text.insert("end", text + "\n", tags)
        self.text.configure(state="disabled")
        if at_end:
            self.text.see("end")

    def _set_verdict(self, v):
        self.v_verdict.set(v)
        self.lbl_verdict.configure(fg=VERDICT_COLOR.get(v, FG))

    def _done(self, rc):
        self.btn_run.configure(state="normal")
        self.btn_stop.configure(state="disabled")
        if self.v_verdict.get() == "running...":
            self.v_verdict.set("no verdict")
            self.lbl_verdict.configure(fg=COLORS["dim"])
        self.v_status.set(f"Finished (interceptor exit code {rc}; 0 = benign, 2 = flagged)")
        self.proc = None

    def _apply_filter(self):
        for k, var in self.show.items():
            self.text.tag_configure("sev_" + k, elide=not var.get())

    def _counts_text(self):
        c = self.counts
        return f"INFO {c['INFO']}   WARN {c['WARN']}   BLOCK {c['BLOCK']}"

    def clear(self):
        self.text.configure(state="normal")
        self.text.delete("1.0", "end")
        self.text.configure(state="disabled")
        self.ioc.delete(0, "end")
        self.counts = {"INFO": 0, "WARN": 0, "BLOCK": 0}
        self.lbl_counts.configure(text=self._counts_text())
        if not self.proc:
            self.v_verdict.set("-")
            self.lbl_verdict.configure(fg=COLORS["dim"])

    def save(self):
        p = filedialog.asksaveasfilename(defaultextension=".txt",
                                         filetypes=[("Text", "*.txt"), ("All", "*")])
        if p:
            with open(p, "w") as f:
                f.write(self.text.get("1.0", "end"))
            self.v_status.set(f"Saved to {p}")


if __name__ == "__main__":
    if not sys.platform.startswith("linux"):
        sys.exit("The interceptor is Linux only.")
    App().mainloop()