#!/usr/bin/env python3
"""
FastAPI Server for Active Threat Interceptor Sandbox.
Binds interceptor.py logic to provide file execution in bubblewrap sandbox,
real-time telemetry streaming (via SSE / WebSocket / JSON), and Gemma AI analysis.
"""
import asyncio
import json
import os
import shutil
import site
import sys
import tempfile
from typing import Optional, List, Dict, Any

# Ensure user site-packages are accessible even when sandboxed/system python is used
user_site = site.getusersitepackages()
if os.path.exists(user_site) and user_site not in sys.path:
    sys.path.insert(0, user_site)

from fastapi import FastAPI, File, UploadFile, Form, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

import interceptor

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = FastAPI(
    title="Active Threat Interceptor Sandbox API",
    description="FastAPI service executing untrusted code securely via bubblewrap and interceptor.py",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class DetonationRequest(BaseModel):
    filename: Optional[str] = "malware.py"
    code: Optional[str] = None
    timeout: float = 10.0
    mode: str = "observe"  # "observe" or "strict"
    net: bool = False
    analyze: bool = False
    gemma_api_key: Optional[str] = None


@app.get("/api/health")
async def health_check():
    """Verify system preflights, bubblewrap, python interpreter, and status."""
    has_bwrap = bool(shutil.which("bwrap"))
    return {
        "status": "healthy" if has_bwrap else "degraded",
        "bubblewrap_installed": has_bwrap,
        "platform": sys.platform,
        "python_version": sys.version,
        "interceptor_file": interceptor.SELF,
    }


@app.post("/api/upload")
async def upload_files(files: List[UploadFile] = File(...)):
    """Upload target scripts/artifacts to the sandbox staging area."""
    uploaded = []
    for file in files:
        safe_name = os.path.basename(file.filename or "uploaded_script.py")
        dest_path = os.path.join(UPLOAD_DIR, safe_name)
        with open(dest_path, "wb") as f:
            content = await file.read()
            f.write(content)
        uploaded.append({
            "name": safe_name,
            "size": len(content),
            "path": dest_path
        })
    return {"status": "success", "count": len(uploaded), "files": uploaded}


@app.get("/api/files")
async def list_files():
    """List all staged files in the sandbox environment."""
    items = []
    for fn in os.listdir(UPLOAD_DIR):
        fp = os.path.join(UPLOAD_DIR, fn)
        if os.path.isfile(fp):
            items.append({
                "name": fn,
                "size": os.path.getsize(fp),
                "modified": os.path.getmtime(fp)
            })
    return {"files": items}


@app.post("/api/detonate")
async def detonate_code(req: DetonationRequest):
    """
    Execute a python script through interceptor.py supervisor and bubblewrap jail,
    collecting all telemetry events, process output, and Gemma AI insights.
    """
    # Determine target file
    target_path = None
    temp_file = None
    if req.code:
        temp_file = tempfile.NamedTemporaryFile(suffix=".py", delete=False, dir=UPLOAD_DIR)
        temp_file.write(req.code.encode("utf-8"))
        temp_file.close()
        target_path = temp_file.name
    elif req.filename:
        # Check in uploads dir or current directory
        p1 = os.path.join(UPLOAD_DIR, os.path.basename(req.filename))
        p2 = os.path.join(BASE_DIR, os.path.basename(req.filename))
        if os.path.isfile(p1):
            target_path = p1
        elif os.path.isfile(p2):
            target_path = p2
        else:
            raise HTTPException(status_code=404, detail=f"Target file '{req.filename}' not found.")

    api_key = req.gemma_api_key or os.environ.get("GEMINI_API_KEY", "")

    # Execute sandbox with interceptor
    result = await run_interceptor_sandbox(
        target_path=target_path,
        timeout=req.timeout,
        mode=req.mode,
        net=req.net,
        analyze=req.analyze,
        api_key=api_key,
    )

    if temp_file and os.path.exists(temp_file.name):
        try:
            os.remove(temp_file.name)
        except OSError:
            pass

    return result


@app.get("/api/detonate/stream")
async def stream_detonation(
    filename: Optional[str] = Query("malware.py"),
    timeout: float = Query(10.0),
    mode: str = Query("observe"),
    net: bool = Query(False),
    analyze: bool = Query(False),
    gemma_api_key: Optional[str] = Query(None),
):
    """
    Server-Sent Events (SSE) streaming endpoint:
    Streams live telemetry events (file reads, network calls, process spawns, and AI analysis)
    in real time as the untrusted code executes inside the sandbox.
    """
    p1 = os.path.join(UPLOAD_DIR, os.path.basename(filename))
    p2 = os.path.join(BASE_DIR, os.path.basename(filename))
    if os.path.isfile(p1):
        target_path = p1
    elif os.path.isfile(p2):
        target_path = p2
    else:
        raise HTTPException(status_code=404, detail=f"File {filename} not found")

    api_key = gemma_api_key or os.environ.get("GEMINI_API_KEY", "")

    async def event_generator():
        async for sse_msg in stream_interceptor_sandbox(
            target_path=target_path,
            timeout=timeout,
            mode=mode,
            net=net,
            analyze=analyze,
            api_key=api_key,
        ):
            yield sse_msg

    return StreamingResponse(event_generator(), media_type="text/event-stream")


async def run_interceptor_sandbox(
    target_path: str,
    timeout: float = 10.0,
    mode: str = "observe",
    net: bool = False,
    analyze: bool = False,
    api_key: str = "",
) -> Dict[str, Any]:
    """Runs interceptor supervisor via async subprocess with pipes."""
    cmd = [
        interceptor.system_python(),
        interceptor.SELF,
        "--timeout", str(timeout),
        "--mode", mode,
    ]
    if net:
        cmd.append("--net")
    if analyze and api_key:
        cmd.append("--analyze")

    cmd.append(target_path)

    env = os.environ.copy()
    if api_key:
        env["GEMINI_API_KEY"] = api_key

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
        cwd=BASE_DIR,
    )

    stdout_bytes, stderr_bytes = await proc.communicate()
    stdout_text = stdout_bytes.decode("utf-8", "replace")
    stderr_text = stderr_bytes.decode("utf-8", "replace")

    events = []
    iocs = []
    rules_verdict = "BENIGN"
    ai_verdict = None
    final_verdict = "BENIGN"

    import re
    strip_ansi = lambda s: re.sub(r'\x1b\[[0-9;]*m', '', s)
    pattern = re.compile(r'^\[\s*([\d\.]+)\]\s+([A-Z0-9\-_]+)\s*(.*)$')

    for raw_line in stderr_text.splitlines():
        line = strip_ansi(raw_line).strip()
        m = pattern.match(line)
        if m:
            t_sec, tag, rest = m.groups()
            if tag in ("INFO", "WARN", "BLOCK"):
                events.append({"time": t_sec, "category": tag, "detail": rest})
            elif tag == "IOC":
                iocs.append(rest)
            elif tag == "RULES-VERD":
                rules_verdict = rest.split()[0]
            elif tag == "AI-VERDICT":
                ai_verdict = rest.split()[0]
            elif tag == "FINAL":
                final_verdict = rest.split()[0]

    return {
        "exit_code": proc.returncode,
        "stdout": stdout_text,
        "stderr": stderr_text,
        "events": events,
        "iocs": iocs,
        "rules_verdict": rules_verdict,
        "ai_verdict": ai_verdict,
        "final_verdict": final_verdict,
    }


async def stream_interceptor_sandbox(
    target_path: str,
    timeout: float = 10.0,
    mode: str = "observe",
    net: bool = False,
    analyze: bool = False,
    api_key: str = "",
):
    """Yields Server-Sent Events (SSE) while the interceptor executes."""
    cmd = [
        interceptor.system_python(),
        interceptor.SELF,
        "--timeout", str(timeout),
        "--mode", mode,
    ]
    if net:
        cmd.append("--net")
    if analyze and api_key:
        cmd.append("--analyze")

    cmd.append(target_path)

    env = os.environ.copy()
    if api_key:
        env["GEMINI_API_KEY"] = api_key

    # Emit START event
    yield f"data: {json.dumps({'type': 'START', 'target': os.path.basename(target_path), 'mode': mode, 'net': net})}\n\n"

    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        env=env,
        cwd=BASE_DIR,
    )

    async def read_stream(stream, stream_name):
        lines = []
        while True:
            line = await stream.readline()
            if not line:
                break
            text = line.decode("utf-8", "replace").rstrip()
            lines.append((stream_name, text))
        return lines

    import re
    strip_ansi = lambda s: re.sub(r'\x1b\[[0-9;]*m', '', s)
    pattern = re.compile(r'^\[\s*([\d\.]+)\]\s+([A-Z0-9\-_]+)\s*(.*)$')

    while proc.returncode is None:
        try:
            line = await asyncio.wait_for(proc.stderr.readline(), timeout=0.1)
            if line:
                raw_text = line.decode("utf-8", "replace").rstrip()
                clean_text = strip_ansi(raw_text).strip()
                m = pattern.match(clean_text)
                cat = "SYSTEM"
                msg = clean_text
                if m:
                    _, tag, rest = m.groups()
                    if tag in ("INFO", "WARN", "BLOCK", "START", "SUMMARY", "IOC", "RULES-VERD", "FINAL", "AI", "AI-VERDICT"):
                        cat = tag
                        msg = rest

                # Translate to UI categories
                ui_cat = "SYSTEM"
                if "open" in msg or cat == "INFO":
                    ui_cat = "FILE_READ" if "open" in msg else "SYSTEM"
                if "socket" in msg or "connect" in msg or "urllib" in msg:
                    ui_cat = "NET_CALL"
                if "subprocess" in msg or "exec" in msg or "fork" in msg or "clone" in msg:
                    ui_cat = "PROC_SPAWN"
                if cat == "BLOCK" or "blocked" in msg.lower():
                    ui_cat = "BLOCKED"
                if cat in ("AI", "AI-VERDICT"):
                    ui_cat = "GEMMA_AI"

                yield f"data: {json.dumps({'type': 'LOG', 'category': ui_cat, 'message': msg, 'raw': clean_text})}\n\n"
        except asyncio.TimeoutError:
            if proc.returncode is not None:
                break

    await proc.wait()

    # Read remaining stdout if any
    stdout_rest = await proc.stdout.read()
    if stdout_rest:
        for l in stdout_rest.decode("utf-8", "replace").splitlines():
            if l.strip():
                yield f"data: {json.dumps({'type': 'LOG', 'category': 'SYSTEM', 'message': f'stdout: {l}'})}\n\n"

    yield f"data: {json.dumps({'type': 'COMPLETE', 'exit_code': proc.returncode})}\n\n"


# Serve Frontend UI directly from the same FastAPI server
@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_file = os.path.join(BASE_DIR, "index.html")
    with open(index_file, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/style.css")
async def serve_css():
    return FileResponse(os.path.join(BASE_DIR, "style.css"), media_type="text/css")


@app.get("/script.js")
async def serve_js():
    return FileResponse(os.path.join(BASE_DIR, "script.js"), media_type="application/javascript")


if os.path.isdir(os.path.join(BASE_DIR, "Design")):
    app.mount("/Design", StaticFiles(directory=os.path.join(BASE_DIR, "Design")), name="design")


if __name__ == "__main__":
    import uvicorn
    print("\n[+] Starting FastAPI Threat Interceptor Server on http://0.0.0.0:8000")
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
