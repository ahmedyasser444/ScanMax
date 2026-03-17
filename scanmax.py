#!/usr/bin/env python3
"""
ScanMax Pro - Integrated Recon + AI analysis (single-file)

Features:
- Controlled concurrency and per-tool rate-limiting
- Batch processing for lists of targets
- Optional Gobuster / ffuf fuzzing (configurable wordlists)
- Subprocess management with timeout & retries
- Saves raw outputs (txt/JSON/CSV) + structured JSON summary
- Optional local HuggingFace model or OpenAI analysis (auto-detect)
- Two-step AI analysis: summarization -> vulnerabilities/CVEs/recommendations
- Robust logging and graceful shutdown (SIGINT)
- Configurable via CLI

Author: Ahmed (ScanMax)
"""

import requests
import argparse
import csv
import json
import logging
import os
import shlex
import signal
import shutil
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn

# ---------- Banner (rich) ----------
console = Console()

def banner():
    ascii_art = r"""
     ____                                 __  ___             
    / ___|  ___ __ _ _ __ ___  _ __ ___  / / / _ \__  ___ ___ 
    \___ \ / __/ _` | '_ ` _ \| '_ ` _ \| | | | | \ \/ / / __|
     ___) | (_| (_| | | | | | | | | | |_| |>  <| \__ \
    |____/ \___\__,_|_| |_| |_|_| |_| |_|_|  \___//_/\_\ |___/
    
             [bold cyan]AI-Powered Recon & Vulnerability Scanner[/bold cyan]
    """
    console.print(Panel(ascii_art, style="bold green", expand=True, border_style="cyan"))
    console.print("[bold yellow]Version:[/bold yellow] 1.0   "
                  "[bold yellow]Author:[/bold yellow] Ahmed444 (ScanMax)\n")
    console.print("[bold magenta]Type '--help' to see CLI options[/bold magenta]\n")

banner()


# ---------- AI helpers ----------

class AIEngine:
    def __init__(self, hf_model=None, openai_api_key=None, ollama_model=None):
        self.hf_model = hf_model
        self.openai_api_key = openai_api_key
        self.ollama_model = ollama_model
        self.hf_pipe = None
        self.initialized = False
        self.init_lock = threading.Lock()

    def initialize(self):
        with self.init_lock:
            if self.initialized:
                return

            # ✅ أول اختيار: Ollama
            if self.ollama_model:
                self.initialized = True
                return

            # ✅ HF
            if self.hf_model and HF_AVAILABLE:
                try:
                    console.print("[green]Loading HF model...[/]")
                    tokenizer = AutoTokenizer.from_pretrained(self.hf_model)
                    model = AutoModelForSeq2SeqLM.from_pretrained(self.hf_model)
                    self.hf_pipe = pipeline("text2text-generation", model=model, tokenizer=tokenizer)
                    self.initialized = True
                    return
                except Exception as e:
                    LOG.exception("HF load failed: %s", e)

            # ✅ OpenAI
            if self.openai_api_key and OPENAI_AVAILABLE:
                openai.api_key = self.openai_api_key
                self.initialized = True
                return

            LOG.warning("No AI backend available")

    # 🔥 Ollama call
    def ollama_generate(self, prompt):
        try:
            res = requests.post(
                "http://localhost:11434/api/generate",
                json={
                    "model": self.ollama_model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": 0.2,
                        "top_p": 0.9
                    }
                },
                timeout=120
            )
            if res.status_code == 200:
                return res.json().get("response", "")
        except Exception as e:
            return f"[Ollama Error] {e}"
        return "[Ollama unavailable]"

    def summarize(self, text, max_length=256):
        self.initialize()

        # ✅ Ollama
        if self.ollama_model:
            return self.ollama_generate(f"Summarize:\n{text}")

        # ✅ HF
        if self.hf_pipe:
            out = self.hf_pipe(text[:2000], max_length=max_length)
            return out[0]["generated_text"]

        # ✅ OpenAI
        if self.openai_api_key and OPENAI_AVAILABLE:
            resp = openai.Completion.create(
                engine="text-davinci-003",
                prompt= f"""
                You are a professional cybersecurity analyst and penetration tester.

                You are given real reconnaissance data from tools like nmap, httpx, and ffuf.

                STRICT RULES:
                - Do NOT hallucinate vulnerabilities.
                - Do NOT guess or assume.
                - If something is unclear, say: "Not enough data".
                - Only base your analysis on the provided data.

                ========================
                TASK 1: SUMMARY
                ========================
                Provide a short structured summary:
                - Open Ports
                - Technologies Detected
                - Interesting Endpoints
                - Key Notes

                ========================
                TASK 2: VULNERABILITY ANALYSIS
                ========================
                - List confirmed or strongly suspected vulnerabilities
                - Explain WHY each is a risk
                - Assign Risk Level (Low / Medium / High)
                - If none found → say: "No confirmed vulnerabilities found."

                ========================
                TASK 3: ATTACK INSIGHTS
                ========================
                - High-value targets
                - Suspicious endpoints
                - Possible entry points for testing

                ========================
                FINAL OUTPUT FORMAT:
                ========================
                ### Summary
                ...

                ### Vulnerabilities
                ...

                ### Attack Insights
                ...

                ========================
                DATA:
                {text[:4000]}
                """ ,
                max_tokens=max_length,
            )
            return resp.choices[0].text.strip()

        return "[AI unavailable]"

    def analyze_vulns(self, text, max_length=512):
        self.initialize()

        if self.ollama_model:
            return self.ollama_generate(
                f"Find vulnerabilities, CVEs, fixes:\n{text}"
            )

        if self.hf_pipe:
            out = self.hf_pipe(text[:1500], max_length=max_length)
            return out[0]["generated_text"]

        if self.openai_api_key and OPENAI_AVAILABLE:
            resp = openai.Completion.create(
                engine="text-davinci-003",
                prompt=f"Analyze vulnerabilities:\n{text}",
                max_tokens=max_length,
            )
            return resp.choices[0].text.strip()

        return "[AI unavailable]"
# ---------- Logging ----------
LOG = logging.getLogger("scanmax_pro")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)

# ---------- Globals & defaults ----------
SHUTDOWN = threading.Event()
DEFAULT_TIMEOUT = 300  # seconds for each subprocess by default
RETRY_COUNT = 2
RETRY_DELAY = 3

# Semaphores to limit per-tool concurrency (changeable through args)
semaphores: Dict[str, threading.Semaphore] = {}

# Optional AI backends detection
HF_AVAILABLE = False
OPENAI_AVAILABLE = False
try:
    from transformers import pipeline, AutoTokenizer, AutoModelForSeq2SeqLM
    HF_AVAILABLE = True
except Exception:
    HF_AVAILABLE = False

try:
    import openai
    OPENAI_AVAILABLE = True
except Exception:
    OPENAI_AVAILABLE = False

# ---------- Utility helpers ----------

def safe_mkdir(path: str):
    Path(path).mkdir(parents=True, exist_ok=True)


def timestamp():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def which_or_warn(cmd: str) -> Optional[str]:
    path = shutil.which(cmd)
    if not path:
        LOG.warning("Tool not found in PATH: %s. Skipping related tasks.", cmd)
    return path


def wait_for_file(path: str, timeout: int = 30, poll: float = 1.0) -> bool:
    """Wait for a file to appear within timeout seconds."""
    start = time.time()
    while time.time() - start < timeout:
        if Path(path).exists() and Path(path).stat().st_size > 0:
            return True
        if SHUTDOWN.is_set():
            return False
        time.sleep(poll)
    return False


def run_subprocess(cmd: str, timeout: int, capture_output: bool = True) -> Dict:
    """Run a shell command with timeout, retries, and return result dict."""
    LOG.debug("Running subprocess: %s", cmd)
    for attempt in range(1, RETRY_COUNT + 1):
        if SHUTDOWN.is_set():
            return {"returncode": -1, "stdout": "", "stderr": "shutdown"}
        try:
            completed = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE if capture_output else None,
                stderr=subprocess.PIPE if capture_output else None,
                text=True,
                timeout=timeout,
                executable='/bin/bash',
            )
            return {
                "returncode": completed.returncode,
                "stdout": completed.stdout if capture_output else "",
                "stderr": completed.stderr if capture_output else "",
            }
        except subprocess.TimeoutExpired:
            LOG.warning("Command timed out (attempt %d/%d): %s", attempt, RETRY_COUNT, cmd)
            if attempt < RETRY_COUNT:
                time.sleep(RETRY_DELAY)
                continue
            return {"returncode": -1, "stdout": "", "stderr": f"timeout after {timeout}s"}
        except Exception as e:
            LOG.exception("Unexpected error running command: %s", cmd)
            return {"returncode": -1, "stdout": "", "stderr": str(e)}


def chunk_text(text: str, max_chars: int = 3000) -> List[str]:
    chunks = []
    current = []
    count = 0
    for line in text.splitlines(keepends=True):
        if count + len(line) > max_chars and current:
            chunks.append("".join(current))
            current = []
            count = 0
        current.append(line)
        count += len(line)
    if current:
        chunks.append("".join(current))
    return chunks


# ---------- FFUF JSON -> CSV helper ----------
def ffuf_json_to_csv(json_path: str, csv_path: str) -> bool:
    """Convert ffuf JSON output to a compact CSV summary.
    CSV columns: subdomain, url, status, length, redirect, words
    Returns True on success.
    """
    try:
        with open(json_path, 'r') as jf:
            data = json.load(jf)
    except Exception as e:
        LOG.exception("Failed to read ffuf JSON %s: %s", json_path, e)
        return False

    results = data.get('results') if isinstance(data, dict) else None
    if not results:
        # ffuf sometimes outputs a top-level list or different structure; try to find results key
        for k in ('results', 'matches', 'hits'):
            if isinstance(data, dict) and k in data and isinstance(data[k], list):
                results = data[k]
                break
    if not isinstance(results, list):
        LOG.warning("ffuf JSON does not contain a results list: %s", json_path)
        return False

    safe_mkdir(Path(csv_path).parent.as_posix())
    try:
        with open(csv_path, 'w', newline='') as cf:
            writer = csv.writer(cf)
            writer.writerow(['subdomain', 'url', 'status', 'length', 'redirect', 'words'])
            for r in results:
                url = r.get('url') or r.get('uri') or ''
                # try to extract domain (subdomain) from url
                subdomain = ''
                try:
                    subdomain = url.split('/')[2]
                except Exception:
                    subdomain = ''
                status = r.get('status') or r.get('status_code') or ''
                length = r.get('length') or r.get('size') or ''
                redirect = r.get('redirect') or r.get('redirect_location') or ''
                words = r.get('words') or r.get('num_words') or ''
                writer.writerow([subdomain, url, status, length, redirect, words])
        return True
    except Exception as e:
        LOG.exception("Failed to write ffuf CSV %s: %s", csv_path, e)
        return False


# ---------- AI helpers 2 ----------
# class AIEngine:
#     def __init__(self, hf_model: Optional[str] = None, openai_api_key: Optional[str] = None):
#         self.hf_model = hf_model
#         self.openai_api_key = openai_api_key
#         self.hf_pipe = None
#         self.initialized = False
#         self.init_lock = threading.Lock()

#     def initialize(self):
#         with self.init_lock:
#             if self.initialized:
#                 return
#             if self.hf_model and HF_AVAILABLE:
#                 try:
#                     console.print("[green]Loading local HF model (may take a moment)...[/]")
#                     tokenizer = AutoTokenizer.from_pretrained(self.hf_model)
#                     model = AutoModelForSeq2SeqLM.from_pretrained(self.hf_model)
#                     self.hf_pipe = pipeline("text2text-generation", model=model, tokenizer=tokenizer)
#                     self.initialized = True
#                     return
#                 except Exception as e:
#                     LOG.exception("Failed to load HF model: %s", e)
#             if self.openai_api_key and OPENAI_AVAILABLE:
#                 openai.api_key = self.openai_api_key
#                 self.initialized = True
#                 return
#             if HF_AVAILABLE:
#                 try:
#                     console.print("[yellow]Falling back to small HF model 'google/flan-t5-small'[/]")
#                     self.hf_pipe = pipeline("text2text-generation", model="google/flan-t5-small")
#                     self.initialized = True
#                     return
#                 except Exception as e:
#                     LOG.exception("Fallback HF model failed: %s", e)
#             LOG.warning("No AI backend available (HF/OpenAI not installed or keys missing). Skipping AI." )

#     def summarize(self, text: str, max_length: int = 256) -> str:
#         self.initialize()
#         if not self.initialized:
#             return "[AI unavailable]"
#         if self.hf_pipe:
#             prompt = f"Summarize the following reconnaissance results in short bullets:\n{text}"
#             chunks = chunk_text(prompt, max_chars=2000)
#             parts = []
#             for c in chunks:
#                 try:
#                     out = self.hf_pipe(c, max_length=max_length, truncation=True)
#                     parts.append(out[0]["generated_text"])
#                 except Exception as e:
#                     LOG.exception("HF summarization failed: %s", e)
#             return "\n".join(parts)
#         if self.openai_api_key and OPENAI_AVAILABLE:
#             try:
#                 resp = openai.Completion.create(
#                     engine="text-davinci-003",
#                     prompt=f"Summarize the following reconnaissance results in short bullets:\n{text}",
#                     max_tokens=max_length,
#                 )
#                 return resp.choices[0].text.strip()
#             except Exception as e:
#                 LOG.exception("OpenAI summarization failed: %s", e)
#                 return "[AI error]"
#         return "[AI unavailable]"

#     def analyze_vulns(self, text: str, max_length: int = 512) -> str:
#         self.initialize()
#         if not self.initialized:
#             return "[AI unavailable]"
#         if self.hf_pipe:
#             prompt = (
#                 "Given the reconnaissance output below, list likely vulnerabilities, map any possible CVE numbers (if known), "
#                 "and give concise remediation advice. Use bullet points.\n" + text
#             )
#             chunks = chunk_text(prompt, max_chars=1500)
#             parts = []
#             for c in chunks:
#                 try:
#                     out = self.hf_pipe(c, max_length=max_length, truncation=True)
#                     parts.append(out[0]["generated_text"])
#                 except Exception as e:
#                     LOG.exception("HF vuln analysis failed: %s", e)
#             return "\n---\n".join(parts)
#         if self.openai_api_key and OPENAI_AVAILABLE:
#             try:
#                 resp = openai.Completion.create(
#                     engine="text-davinci-003",
#                     prompt= (
#                         "Given the reconnaissance output below, list likely vulnerabilities, map any possible CVE numbers (if known), "
#                         "and give concise remediation advice. Use bullet points.\n" + text
#                     ),
#                     max_tokens=max_length,
#                 )
#                 return resp.choices[0].text.strip()
#             except Exception as e:
#                 LOG.exception("OpenAI vuln analysis failed: %s", e)
#                 return "[AI error]"
#         return "[AI unavailable]"


# ---------- Build & run commands ----------

def build_initial_commands(target: str, tools: List[str], level: str, speed: str, ports: Optional[str], output_dir: str) -> List[Dict]:
    ts = timestamp()
    cmds = []
    # Nmap
    if "nmap" in tools:
        port_option = f"-p {ports}" if ports else ""
        speed_flag = speed[-1] if speed and speed.startswith("T") else "3"
        if level == "light":
            cmd = f"nmap -T{speed_flag} -F {port_option} {shlex.quote(target)} -oN {shlex.quote(output_dir)}/nmap_{target}_{ts}.txt"
        elif level == "medium":
            cmd = f"nmap -sC -sV {port_option} -T{speed_flag} {shlex.quote(target)} -oN {shlex.quote(output_dir)}/nmap_{target}_{ts}.txt"
        else:
            cmd = f"nmap -sC -sV -A {port_option} -T{speed_flag} {shlex.quote(target)} -oN {shlex.quote(output_dir)}/nmap_{target}_{ts}.txt"
        cmds.append({"name": "nmap", "cmd": cmd, "outfile": f"{output_dir}/nmap_{target}_{ts}.txt"})

    # Subfinder (we write to a known file to be consumed later)
    if "subfinder" in tools:
        sub_file = f"{output_dir}/subdomains_{target}_{ts}.txt"
        cmd = f"subfinder -d {shlex.quote(target)} -silent -o {shlex.quote(sub_file)}"
        cmds.append({"name": "subfinder", "cmd": cmd, "outfile": sub_file})

    return cmds


def build_followup_commands(target: str, tools: List[str], output_dir: str, ts: str, wordlist: Optional[str], gobuster_threads: int, ffuf_threads: int) -> List[Dict]:
    """Build httpx/gobuster/ffuf commands after subfinder has produced subdomains file."""
    cmds = []
    sub_file = f"{output_dir}/subdomains_{target}_{ts}.txt"
    httpx_out = f"{output_dir}/httpx_{target}_{ts}.txt"
    if "httpx" in tools:
        cmds.append({"name": "httpx", "cmd": f"httpx -l {shlex.quote(sub_file)} -o {shlex.quote(httpx_out)} -silent", "outfile": httpx_out, "depends_on": sub_file})

    # Gobuster/ffuf are set up as per-subdomain jobs later; here just placeholders
    if "gobuster" in tools and wordlist:
        cmds.append({"name": "gobuster", "cmd": None, "outfile": None, "depends_on": sub_file, "per_subdomain": True, "wordlist": wordlist, "threads": gobuster_threads})

    if "ffuf" in tools and wordlist:
        cmds.append({"name": "ffuf", "cmd": None, "outfile": None, "depends_on": sub_file, "per_subdomain": True, "wordlist": wordlist, "threads": ffuf_threads})

    return cmds


def run_tool_with_semaphore(task: Dict, timeout: int, capture_output: bool, dry_run: bool = False):
    name = task["name"]
    cmd = task.get("cmd")
    sem = semaphores.get(name)
    if sem:
        acquired = sem.acquire(timeout=10)
        if not acquired:
            LOG.warning("Could not acquire semaphore for %s, skipping", name)
            return {"name": name, "skipped": True}
    try:
        if dry_run:
            console.print(f"[yellow][DRY RUN][/yellow] {name}: {cmd}")
            return {"name": name, "returncode": 0, "stdout": "", "stderr": ""}
        if cmd is None:
            return {"name": name, "returncode": -1, "stdout": "", "stderr": "no command"}
        res = run_subprocess(cmd, timeout=timeout, capture_output=capture_output)
        return {"name": name, **res}
    finally:
        if sem:
            sem.release()


# ---------- Main target processing ----------

def process_target(target: str, args, ai_engine: Optional[AIEngine]) -> Dict:
    output_dir = args.output
    safe_mkdir(output_dir)
    ts = timestamp()
    target_summary = {"target": target, "timestamp": ts, "files": {}, "ai": {}}

    # Build and run initial cmds (nmap, subfinder)
    initial_cmds = build_initial_commands(target, args.tools, args.level, args.speed, args.ports, output_dir)
    for task in initial_cmds:
        LOG.info("Running %s for %s", task["name"], target)
        res = run_tool_with_semaphore(task, timeout=args.timeout, capture_output=True, dry_run=args.dry_run)
        outfile = task.get("outfile")
        # If the tool wrote stdout and outfile is expected, write it
        if outfile and res.get("stdout"):
            try:
                with open(outfile, "w") as f:
                    f.write(res.get("stdout", ""))
            except Exception as e:
                LOG.exception("Writing outfile failed: %s", e)
        target_summary["files"][task["name"]] = {"returncode": res.get("returncode"), "outfile": outfile}

    # Build follow-up cmds (httpx, gobuster, ffuf) which depend on subdomains file
    followup_cmds = build_followup_commands(target, args.tools, output_dir, ts, args.wordlist, args.gobuster_threads, args.ffuf_threads)

    # Wait for subdomains file if needed
    sub_file = f"{output_dir}/subdomains_{target}_{ts}.txt"
    if any(task.get("depends_on") == sub_file or task.get("depends_on") for task in followup_cmds):
        if not wait_for_file(sub_file, timeout=args.dep_wait):
            LOG.info("Subdomains file not ready or empty: %s. Proceeding with fallbacks.", sub_file)
        else:
            LOG.info("Subdomains file ready: %s", sub_file)

        # Run httpx first if requested
        for task in followup_cmds:
            if task["name"] == "httpx":
                LOG.info("Running httpx for %s", target)
                res = run_tool_with_semaphore(task, timeout=args.timeout, capture_output=True, dry_run=args.dry_run)
                outfile = task.get("outfile")
                if outfile and res.get("stdout"):
                    try:
                        with open(outfile, "w") as f:
                            f.write(res.get("stdout", ""))
                    except Exception as e:
                        LOG.exception("Writing outfile failed: %s", e)
                target_summary["files"][task["name"]] = {"returncode": res.get("returncode"), "outfile": outfile}

        # Prepare subdomains list (might be empty)
        subdomains: List[str] = []
        if Path(sub_file).exists() and Path(sub_file).stat().st_size > 0:
            try:
                with open(sub_file, "r") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            # normalize: remove protocol
                            sd = line.replace("https://", "").replace("http://", "")
                            subdomains.append(sd)
            except Exception as e:
                LOG.exception("Failed to read subdomains file: %s", e)

        # If subdomains empty, fallback to target itself
        if not subdomains:
            LOG.info("No subdomains found for %s; falling back to target root for fuzzing", target)
            subdomains = [target]

        # Validate wordlist if fuzzing requested
        if (args.use_gobuster or args.use_ffuf) and not args.wordlist:
            # try default common wordlist
            default_w = "/usr/share/wordlists/dirb/common.txt"
            if Path(default_w).exists():
                args.wordlist = default_w
                LOG.info("No --wordlist provided; using default: %s", default_w)
            else:
                LOG.warning("No wordlist specified and default was not found; skipping gobuster/ffuf")

        # Run per-subdomain gobuster/ffuf jobs
        for sd in subdomains:
            sd_clean = sd.replace("https://", "").replace("http://", "")
            if args.use_gobuster and args.wordlist:
                out_path = f"{output_dir}/gobuster_{sd_clean}_{ts}.txt"
                cmd = f"gobuster dir -u http://{sd_clean} -w {shlex.quote(args.wordlist)} -o {shlex.quote(out_path)} -q -t {args.gobuster_threads}"
                task = {"name": "gobuster", "cmd": cmd, "outfile": out_path}
                LOG.info("Running gobuster on %s", sd_clean)
                res = run_tool_with_semaphore(task, timeout=args.timeout, capture_output=True, dry_run=args.dry_run)
                # if tool printed output but didn't write file, write it
                try:
                    if res.get("stdout") and not Path(out_path).exists():
                        with open(out_path, "w") as f:
                            f.write(res.get("stdout", ""))
                except Exception as e:
                    LOG.exception("Failed to write gobuster output: %s", e)
                # record per-subdomain results
                if "gobuster" not in target_summary["files"]:
                    target_summary["files"]["gobuster"] = []
                target_summary["files"]["gobuster"].append({"subdomain": sd_clean, "returncode": res.get("returncode"), "outfile": out_path})

            if args.use_ffuf and args.wordlist:
                out_path = f"{output_dir}/ffuf_{sd_clean}_{ts}.json"
                cmd = f"ffuf -w {shlex.quote(args.wordlist)} -u http://{sd_clean}/FUZZ -o {shlex.quote(out_path)} -of json -t {args.ffuf_threads}"
                task = {"name": "ffuf", "cmd": cmd, "outfile": out_path}
                LOG.info("Running ffuf on %s", sd_clean)
                res = run_tool_with_semaphore(task, timeout=args.timeout, capture_output=True, dry_run=args.dry_run)
                try:
                    if res.get("stdout") and not Path(out_path).exists():
                        with open(out_path, "w") as f:
                            f.write(res.get("stdout", ""))
                except Exception as e:
                    LOG.exception("Failed to write ffuf output: %s", e)
                if "ffuf" not in target_summary["files"]:
                    target_summary["files"]["ffuf"] = []
                target_summary["files"]["ffuf"].append({"subdomain": sd_clean, "returncode": res.get("returncode"), "outfile": out_path})

                # Convert ffuf JSON to CSV summary and store path
                csv_path = out_path.replace('.json', '.csv')
                ok = ffuf_json_to_csv(out_path, csv_path)
                if ok:
                    target_summary["files"]["ffuf"][-1]["csv_summary"] = csv_path

    # Save structured summary (raw)
    structured_file = f"{output_dir}/summary_{target}_{ts}.json"
    with open(structured_file, "w") as f:
        json.dump(target_summary, f, indent=2)
    target_summary["structured_file"] = structured_file

    # AI analysis
    # Combine readable text from available output files
    all_text = ""
    for k, info in target_summary["files"].items():
        if isinstance(info, list):
            for item in info:
                fp = item.get("outfile")
                if fp and Path(fp).exists() and Path(fp).stat().st_size > 0:
                    try:
                        with open(fp, "r") as f:
                            content = f.read()
                            all_text += f"\n--- {k} ({fp}) ---\n"
                            all_text += content
                    except Exception as e:
                        LOG.exception("Failed reading %s: %s", fp, e)
        else:
            fp = info.get("outfile")
            if fp and Path(fp).exists() and Path(fp).stat().st_size > 0:
                try:
                    with open(fp, "r") as f:
                        content = f.read()
                        all_text += f"\n--- {k} ({fp}) ---\n"
                        all_text += content
                except Exception as e:
                    LOG.exception("Failed reading %s: %s", fp, e)

    if not args.skip_ai and all_text.strip():
        if ai_engine:
            console.print(f"[cyan]Running AI analysis for {target}...[/]")
            summary = ai_engine.summarize(all_text, max_length=220)
            vulns = ai_engine.analyze_vulns(all_text, max_length=512)
            report_md = []
            report_md.append("# ScanMax AI Analysis Report")
            report_md.append(f"**Target:** {target}\n**Timestamp:** {ts}\n")
            report_md.append("## Summary")
            report_md.append(summary)
            report_md.append("\n## Potential Vulnerabilities & CVEs")
            report_md.append(vulns)

            reports_dir = Path(args.reports)
            reports_dir.mkdir(parents=True, exist_ok=True)
            report_file = reports_dir / f"{target}_ai_report_{ts}.md"
            with open(report_file, "w") as f:
                f.write("\n\n".join(report_md))
            target_summary["ai"]["report_file"] = str(report_file)
            console.print(f"[green]AI report saved to:[/] {report_file}")
        else:
            LOG.warning("AI engine not provided; skipping AI analysis")
    else:
        LOG.info("Skipping AI analysis (either skip flag or no data)")

    return target_summary


# ---------- CLI & Orchestration ----------

def handle_sigint(signum, frame):
    LOG.warning("SIGINT received: initiating graceful shutdown...")
    SHUTDOWN.set()


def parse_args():
    parser = argparse.ArgumentParser(description="ScanMax Pro - Recon + AI (controlled, pro)")
    parser.add_argument("targets", nargs="*", help="Target domain(s) or IP(s)")
    parser.add_argument("--targets-file", help="File with one target per line")
    parser.add_argument("-t", "--tools", nargs="+", default=["nmap", "subfinder", "httpx"], help="Tools to run")
    parser.add_argument("-l", "--level", choices=["light", "medium", "full"], default="medium", help="Scan level")
    parser.add_argument("--speed", choices=["T1", "T2", "T3", "T4", "T5"], default="T3", help="Nmap speed+aggressiveness")
    parser.add_argument("-o", "--output", default="results", help="Output directory for raw tool outputs")
    parser.add_argument("--reports", default="reports", help="Directory for AI reports")
    parser.add_argument("--threads", type=int, default=3, help="Max concurrent targets to process")
    parser.add_argument("--per-tool-concurrency", type=int, default=2, help="Max concurrent runs per tool (semaphores)")
    parser.add_argument("--batch-size", type=int, default=5, help="Run tools in batches for a large list of targets")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Timeout per tool subprocess (s)")
    parser.add_argument("--skip-ai", action="store_true", help="Skip AI analysis")
    parser.add_argument("--hf-model", help="Local HF model name/path (e.g., google/flan-t5-small) to use for AI analysis")
    parser.add_argument("--openai-key", help="OpenAI API key (optional)")
    parser.add_argument("--ports", help="Ports for nmap (e.g., 1-1000 or 22,80,443)")
    parser.add_argument("--dry-run", action="store_true", help="Show planned commands but do not execute")
    parser.add_argument("--verbose", action="store_true", help="Verbose logging")

    # Fuzzing options
    parser.add_argument("--wordlist", help="Wordlist for gobuster/ffuf (required if using these tools)")
    parser.add_argument("--use-gobuster", action="store_true", help="Enable gobuster dir fuzzing per discovered subdomain")
    parser.add_argument("--gobuster-threads", type=int, default=10, help="Gobuster threads per job")
    parser.add_argument("--use-ffuf", action="store_true", help="Enable ffuf fuzzing per discovered subdomain")
    parser.add_argument("--ffuf-threads", type=int, default=10, help="ffuf threads per job")

    parser.add_argument("--dep-wait", type=int, default=30, help="Seconds to wait for dependent files (subdomains) to appear")

    parser.add_argument("--ollama-model", help="Use Ollama model (e.g., mistral:7b)")

    return parser.parse_args()


def main():
    args = parse_args()
    if args.verbose:
        LOG.setLevel(logging.DEBUG)

    # Collect targets
    targets: List[str] = list(args.targets or [])
    if args.targets_file:
        with open(args.targets_file, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    targets.append(line)
    if not targets:
        console.print("[red]No targets provided. See --help.[/]")
        sys.exit(1)

    # prepare semaphores per tool
    tools_set = set(args.tools)
    if args.use_gobuster:
        tools_set.add("gobuster")
    if args.use_ffuf:
        tools_set.add("ffuf")

    for tool in tools_set:
        semaphores[tool] = threading.Semaphore(args.per_tool_concurrency)

    # Check presence of external tools and warn early
    for t in ("nmap", "subfinder", "httpx", "gobuster", "ffuf"):
        if t in tools_set:
            which_or_warn(t)

    # AI engine
    ai_engine = None
    if not args.skip_ai:
        ai_engine = AIEngine(
            hf_model=args.hf_model,
            openai_api_key=args.openai_key,
            ollama_model=args.ollama_model
        )

    safe_mkdir(args.output)
    safe_mkdir(args.reports)

    signal.signal(signal.SIGINT, handle_sigint)

    results = []
    with ThreadPoolExecutor(max_workers=args.threads) as exc:
        futures = {exc.submit(process_target, t, args, ai_engine): t for t in targets}
        try:
            for fut in as_completed(futures):
                if SHUTDOWN.is_set():
                    LOG.info("Shutdown requested: skipping remaining results")
                    break
                target = futures[fut]
                try:
                    res = fut.result()
                    results.append(res)
                except Exception as e:
                    LOG.exception("Error processing target %s: %s", target, e)
        except KeyboardInterrupt:
            LOG.warning("KeyboardInterrupt: shutting down executor")
            SHUTDOWN.set()

    # save master summary
    master_file = Path(args.output) / f"master_summary_{timestamp()}.json"
    with open(master_file, "w") as f:
        json.dump(results, f, indent=2)
    console.print(f"[green]All done. Master summary saved to {master_file}[/]")


if __name__ == "__main__":
    main()
