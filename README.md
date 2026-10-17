# Little-Sandbox

**Active Threat Interceptor**: a small, zero-dependency tool for answering one question quickly: *"what does this sketchy Python script actually do?"*

You point it at a script. It runs the script inside a locked-down box, watches everything the script tries to do (read files, open sockets, spawn shells), and prints a live, colour-coded log. At the end you get a verdict and a list of indicators (IPs, files, commands). Optionally, Gemma gives a second opinion in plain English.

You can use it from the command line or from a simple desktop GUI.

We built it for a hackathon, mostly for CTF challenges and for looking at third-party scripts we didn't trust, without spinning up Docker or a full VM every time.

> **Read this first:** this is a triage tool, not a vault. It's good at the boring, common cases but nothing too fancy.

---

## What's in the repo

| File | What it is |
| --- | --- |
| `interceptor.py` | The engine. A command-line tool: supervisor, jail launcher, audit hook, dashboard and AI analyst, all in one file. |
| `gui.py` | A Tkinter desktop front-end that runs `interceptor.py` for you and shows the results in a window. |
| `malware.py` | Test sample: tries to write a file, connect to `8.8.8.8:53`, and run `whoami`. |
| `reverse_shell.py` | Test sample: the classic reverse-shell pattern (connect out, wire the socket to a shell). |
| `testing.py` | A harmless NumPy script. Useful for seeing how the jail handles pip packages. |

## How it works

The tool is split in two so the script being analysed can't mess with the thing watching it.

```
supervisor (outside the jail)
   │  starts, through bubblewrap:
   │    - no network
   │    - read-only system files, empty /tmp
   │    - its own process space, no capabilities
   ▼
child (inside the jail)
   │  sets resource limits, installs the audit hook
   ▼
your script runs here
```

- **The jail (bubblewrap)** does the real enforcement. There's no network card to connect through, and files like `/etc/shadow` or your home folder simply don't exist inside it.
- **The audit hook (`sys.addaudithook`)** is the camera. Python announces events like "opening a file" or "connecting a socket", and we record them and stream them to the supervisor over a private pipe.
- **The supervisor** draws the dashboard, enforces a wall-clock timeout, and kills the whole process group if the script hangs or floods the log.
- **Resource limits** cap CPU time, memory, file size and open files, so a runaway script can't eat your machine.

The engine is standard library Python only. No pip installs. (The GUI needs Tk, see below.)

## Requirements

- Linux (built and tested on Ubuntu)
- Python 3.8+, the **system** Python under `/usr` (not a venv or pyenv)
- bubblewrap: `sudo apt install bubblewrap`
- For the GUI: Tk, via `sudo apt install python3-tk`
- For the optional AI analysis: a Google AI Studio API key and an internet connection

## Quick start (command line)

```bash
git clone https://github.com/shubham270706/Little-Sandbox.git
cd Little-Sandbox

python3 interceptor.py malware.py
```

`malware.py` tries to touch a file, phone home to `8.8.8.8`, and run a shell command. Inside the jail the file doesn't exist and the network is unreachable, but you still see every attempt logged. That's the point: you learn *what* it tried to do and *where* it tried to connect.

### Options

| Flag | What it does |
| --- | --- |
| `--timeout N` | Kill the script after N seconds (default 10) |
| `--strict` | Make the audit hook kill dangerous actions instead of just logging them |
| `--analyze` | Send a summarised event list to Gemma for a second opinion |
| `--log FILE` | Save events as JSON lines |
| `--net` | Share the host network. **Not recommended**, it defeats the jail |
| `--max-events N` | Kill the script if it floods the log (default 20000) |

```bash
python3 interceptor.py malware.py --analyze --timeout 15 -- --its-own-flag value
```

## Quick start (GUI)

```bash
sudo apt install python3-tk
/usr/bin/python3 gui.py
```

Keep `gui.py` next to `interceptor.py`. Use the **system** Python (`/usr/bin/python3`), because the interceptor refuses venv and pyenv interpreters, and the GUI checks for that before it runs anything.

What you get:

- **Target:** pick the script and, optionally, its arguments.
- **Sandbox:** an Observe / Strict switch, a time limit, and a "Share host network" checkbox (it asks you to confirm, because it defeats the jail).
- **AI triage:** a checkbox plus API key and model fields. The key box is pre-filled from `GEMINI_API_KEY` if you've exported it. The key is handed to the interceptor through the environment for that run, and the GUI doesn't save it anywhere.
- **Advanced:** the path to the interceptor, an optional JSONL log file, and the max-events limit.
- **Verdict card:** the current verdict, a progress bar against the time limit, and live counts of info, warning and blocked events.
- **Live log:** colour-coded, with filter chips (Info, Warnings, Blocked, Script output), plus **Save log** and **Clear**.
- **Indicators:** the IPs, domains and files the script went for, with a **Copy** button.
- **Analyst notes:** the AI's summary and findings, when AI triage is on.

Shortcuts: `Ctrl+Enter` runs, `Esc` stops, `Ctrl+L` clears the log.

## Observe vs. Strict

By default the tool runs in **observe mode**: the script keeps running and we log everything. We think this is the right default for triage. If the script gets killed at its first `os.system`, you never see its second stage, its fallback server, or the files it drops. The jail is what keeps this safe.

A few things are denied even in observe mode, because they'd blind the camera or touch the kernel directly: loading native code through `ctypes`, `ptrace`, and `setuid`. Process spawning is allowed but capped at a small budget so a fork bomb can't take your machine down.

Add `--strict` (or pick **Strict** in the GUI) when you want a hard stop on anything dangerous.

## The AI second opinion (optional)

```bash
export GEMINI_API_KEY="your-key"
python3 interceptor.py malware.py --analyze
```

After the run, the supervisor sends a deduplicated, sanitised list of events (not the script's output) to Gemma through the Gemini API. Gemma returns a verdict, a confidence, and findings that cite specific event numbers. The default model is `gemma-4-26b-a4b-it`; override it with the `ATI_MODEL` environment variable (or the Model field in the GUI).

A few rules we set for ourselves:

- **The AI can only raise the verdict, never lower it.** If the rules say `SUSPICIOUS` and Gemma says `BENIGN`, you still get `SUSPICIOUS`. That way, a sample that tries to sweet-talk the model gains nothing.
- **Evidence is checked.** Findings that cite events that don't exist are thrown away.
- **Everything from the script is treated as data, not instructions**, and control characters are stripped before anything is printed.
- **It fails quietly.** If the API errors or the reply isn't usable JSON, you still get the normal rule-based verdict.
- **It retries.** If the API is busy (HTTP 429 or 5xx) or the network blips, it tries up to 4 more times, 10 seconds apart, before giving up.

**Privacy:** `--analyze` sends file paths, IPs, domains and event names to Google. Fine for CTF samples. Don't use it on anything confidential or a real incident.

## Reading the output

Here's roughly what a run of `malware.py` looks like (abridged):

```
START       detonating malware.py (timeout 10.0s, network OFF, mode observe)
INFO        open /home/<you>/Desktop/important_stuff.txt
WARN        socket.connect ('8.8.8.8', 53)
WARN        subprocess.Popen observed+allowed: 'whoami' ['whoami'] None None
            | stdout: FAILED (File): [Errno 2] No such file or directory: ...
            | stdout: FAILED (Network): [Errno 101] Network is unreachable
            | stdout: SUCCESS: Executed shell command!
SUMMARY     events=... warn=2 block=0 exit=0
IOC         socket.connect: ('8.8.8.8', 53)
IOC         subprocess.Popen: observed+allowed: 'whoami' ['whoami'] None None
RULES-VERD  SUSPICIOUS  (from sandbox rules only)
FINAL       SUSPICIOUS  (triage only)
```

- **Rules verdict:** `BENIGN`, `SUSPICIOUS`, or `BLOCKED`, from the sandbox alone.
- **AI verdict** (with `--analyze`): `BENIGN`, `SUSPICIOUS`, or `MALICIOUS`, shown in its own block.
- **FINAL:** the combined result. The exit code is `0` only when it's `BENIGN`, so you can use this in scripts.
- **IOC list:** the network targets and flagged actions the script went for.

## The sample scripts

These are test material for the sandbox. **Don't run them directly on your machine.** Always run them through the interceptor.

| Script | What it tries | What you should see |
| --- | --- | --- |
| `malware.py` | Appends to a file under a home folder, connects to `8.8.8.8:53`, runs `whoami` | The file attempt fails (it doesn't exist in the jail), the connection fails (no network), the shell command runs and is logged. Verdict: `SUSPICIOUS`. |
| `reverse_shell.py` | Connects out to `10.0.0.1:4242`, then hands a shell to the socket | The connection attempt is logged as an IOC. Run it with `--strict` to see the hook deny the shell spawn as well. |
| `testing.py` | Imports NumPy and does some array maths | Nothing malicious. It's a good check of the pip-package behaviour below. |

Note that `malware.py` has a path hard-coded to my Desktop. It's harmless inside the jail, but change it if you want the sample to make sense on your machine.

### A note on pip packages

The jail only mounts the system's `/usr`, so a script can import a package only if it lives there: apt-installed (`python3-numpy`) or installed with `sudo pip`. If you installed NumPy with `pip install --user` or inside a venv, `testing.py` will fail with `ModuleNotFoundError` inside the jail. That's the jail doing its job, not a bug, and for a suspicious script a missing import is often useful evidence in itself.

## Limitations

We'd rather say this up front than have you find out the hard way.

- **It's a triage tool, not a hardened sandbox.** It stops everyday malware and CTF payloads. It will not stop someone with a Linux kernel exploit. For genuinely dangerous samples, run the whole thing inside a throwaway VM.
- **`sys.addaudithook` is a tripwire.** Python's own docs say so. It only sees what the Python runtime announces, and a script that shares the process can detect that it's being watched.
- **No seccomp filter yet.** That's the biggest gap: raw syscalls that don't go through Python aren't filtered at the kernel level.
- **The telemetry pipe can be tampered with.** The script can write fake events to it or close it. The supervisor doesn't trust labels coming from the child, but a determined script could still add noise or go quiet.
- **Python scripts only**, on **Linux only**.
- **The GUI reads the interceptor's terminal output.** If the log format changes, `gui.py` needs a matching update.
- **The AI is advisory.** Small models make mistakes, so treat its output as a second pair of eyes, not a verdict you can rely on alone.



## Contributing

Issues and PRs are welcome. If you find a way for a script to get out of the jail, or to hide from the log, please open an issue. That's exactly the kind of thing we want to know about.

## License

[LICENSE](LICENSE)

## Acknowledgements

Built on [bubblewrap](https://github.com/containers/bubblewrap), Python's `sys.addaudithook`, Tkinter, and Google's Gemma models.
