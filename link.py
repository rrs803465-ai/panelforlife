#!/usr/bin/env python3
"""
link.py — Panel4Life node linker

Drop this single file on the second server.
Run:  python3 link.py

It will:
  1. Ask for the primary panel URL and the 8-digit node code.
  2. Detect this machine's public IP and build its own URL.
  3. POST to the primary panel's /api/node/pair endpoint.
  4. On success, run the LXD bootstrap (lxd init --auto, image copy, ZFS pool).
  5. Keep running forever, pushing stats to the primary node every 60s
     so the admin nodes tab stays live.

The process must stay running — use screen, tmux, or systemd.
It does not start a web server. It is a pure background agent.
"""

import sys
import os
import time
import json
import socket
import subprocess
import threading
import urllib.request
import urllib.error

# ── Python version guard ─────────────────────────────────────────────────────
if sys.version_info < (3, 8):
    sys.exit("Python 3.8+ required.")

# ── Optional requests import (falls back to urllib) ──────────────────────────
try:
    import requests as _requests
    def _post(url, payload, headers, timeout=30):
        r = _requests.post(url, json=payload, headers=headers, timeout=timeout)
        return r.status_code, r.json() if r.content else {}
    def _get_json(url, timeout=10):
        r = _requests.get(url, timeout=timeout)
        return r.status_code, r.json() if r.content else {}
except ImportError:
    import json as _json
    def _post(url, payload, headers, timeout=30):
        data = _json.dumps(payload).encode()
        req  = urllib.request.Request(url, data=data, headers={
            **headers, "Content-Type": "application/json"
        }, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read()
                return resp.status, _json.loads(body) if body else {}
        except urllib.error.HTTPError as e:
            body = e.read()
            return e.code, _json.loads(body) if body else {}
    def _get_json(url, timeout=10):
        req = urllib.request.Request(url)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read()
                return resp.status, _json.loads(body) if body else {}
        except urllib.error.HTTPError as e:
            return e.code, {}


# ── Helpers ───────────────────────────────────────────────────────────────────

BOLD  = "\033[1m"
GREEN = "\033[32m"
CYAN  = "\033[36m"
WARN  = "\033[33m"
ERR   = "\033[31m"
RST   = "\033[0m"

def p(msg, color=""):    print(f"{color}{msg}{RST}")
def ok(msg):             p(f"  ✓  {msg}", GREEN)
def warn(msg):           p(f"  !  {msg}", WARN)
def err(msg):            p(f"  ✗  {msg}", ERR)
def banner(msg):         p(f"\n{'─'*54}\n  {msg}\n{'─'*54}", CYAN)


def detect_public_ip() -> str:
    """Best-effort public IP detection via several providers."""
    providers = [
        "https://api.ipify.org",
        "https://ipv4.icanhazip.com",
        "https://checkip.amazonaws.com",
    ]
    for url in providers:
        try:
            with urllib.request.urlopen(url, timeout=5) as r:
                ip = r.read().decode().strip()
                if ip:
                    return ip
        except Exception:
            continue
    # fallback: LAN IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def run_cmd(cmd: list, label: str, timeout: int = 600) -> bool:
    """Runs a command, prints output live, returns True on success."""
    p(f"\n  $ {' '.join(cmd)}", CYAN)
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        for line in proc.stdout:
            print(f"      {line}", end="")
        proc.wait(timeout=timeout)
        if proc.returncode == 0:
            ok(f"{label} done.")
            return True
        else:
            warn(f"{label} exited with code {proc.returncode} — continuing anyway.")
            return False
    except FileNotFoundError:
        warn(f"Command not found: {cmd[0]}  — is LXD installed? (snap install lxd)")
        return False
    except subprocess.TimeoutExpired:
        warn(f"{label} timed out after {timeout}s.")
        return False
    except Exception as e:
        warn(f"{label} error: {e}")
        return False


def lxd_bootstrap():
    """Runs the three LXD setup commands required to provision VPS containers."""
    banner("LXD bootstrap")
    p("Setting up LXD so this node can provision VPS containers…")

    run_cmd(["lxd", "init", "--auto"],                                          "lxd init")
    run_cmd(["lxc", "image", "copy", "ubuntu:22.04", "local:",
             "--alias", "ubuntu/22.04"],                                         "Ubuntu 22.04 image")
    run_cmd(["lxc", "storage", "create", "zfs-new", "zfs", "size=6144GB"],      "ZFS pool")

    ok("Bootstrap complete. This node is ready to receive overflow VPSes.")


def get_host_stats() -> dict:
    cpu_cores = os.cpu_count() or 1
    ram_mb = 0
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    ram_mb = int(line.split()[1]) // 1024
                    break
    except Exception:
        pass
    disk_gb = 0
    try:
        st = os.statvfs("/")
        disk_gb = (st.f_blocks * st.f_frsize) // (1024 ** 3)
    except Exception:
        pass
    vps_count = 0
    try:
        out = subprocess.run(
            ["lxc", "list", "--format=json"],
            capture_output=True, text=True, timeout=10
        ).stdout
        containers = json.loads(out)
        vps_count = sum(1 for c in containers if c.get("name","").startswith("vps-"))
    except Exception:
        pass
    return {
        "vps_count": vps_count,
        "cpu_cores": cpu_cores,
        "ram_mb":    ram_mb,
        "disk_gb":   disk_gb,
    }


# ── State file — persists pairing info across restarts ───────────────────────

STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".link_state.json")

def load_state() -> dict:
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except Exception:
        return {}

def save_state(state: dict):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(state, f, indent=2)
    except Exception as e:
        warn(f"Could not save state: {e}")


# ── Stats push loop ───────────────────────────────────────────────────────────

def stats_loop(primary_url: str, shared_secret: str, my_url: str):
    """Pushes this node's stats to the primary node every 60s."""
    p("\n  Stats push loop started (every 60s). Keep this process running.", CYAN)
    while True:
        try:
            stats = get_host_stats()
            code, resp = _post(
                f"{primary_url}/api/node/stats",
                stats,
                headers={
                    "X-Node-Url":    my_url,
                    "Authorization": shared_secret,
                },
                timeout=10,
            )
            if code != 200:
                warn(f"Stats push returned HTTP {code}: {resp}")
        except Exception as e:
            warn(f"Stats push failed: {e}")
        time.sleep(60)


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    banner("Panel4Life — Node Linker")
    p("This tool links this machine as a peer node to an existing panel.")
    p("Keep it running in the background (screen / tmux / systemd).\n")

    state = load_state()

    # ── Already paired — skip setup ──────────────────────────────────────────
    if state.get("shared_secret") and state.get("primary_url") and state.get("my_url"):
        ok(f"Already paired with {state['primary_url']}")
        p(f"  My URL:  {state['my_url']}")
        p(f"  Secret:  {state['shared_secret'][:8]}…")
        resume = input("\n  Resume stats loop? [Y/n]: ").strip().lower()
        if resume in ("", "y", "yes"):
            stats_loop(state["primary_url"], state["shared_secret"], state["my_url"])
            return
        p("  Starting fresh pairing…")

    # ── Collect inputs ───────────────────────────────────────────────────────
    print()
    primary_url = input("  Primary panel URL (e.g. https://panel.example.com): ").strip().rstrip("/")
    if not primary_url:
        err("URL is required."); sys.exit(1)
    if not primary_url.startswith("http"):
        primary_url = "http://" + primary_url

    node_code = input("  8-digit node code from primary panel console: ").strip()
    if len(node_code) != 8 or not node_code.isdigit():
        err("Code must be exactly 8 digits."); sys.exit(1)

    # ── Detect my public URL ─────────────────────────────────────────────────
    print()
    p("  Detecting this server's public IP…")
    my_ip   = detect_public_ip()
    my_port = input(f"  Port this node runs on [5000]: ").strip() or "5000"
    my_url  = f"http://{my_ip}:{my_port}"
    ok(f"This node's URL: {my_url}")

    override = input(f"  Use a different URL for this node? (leave blank to keep): ").strip()
    if override:
        my_url = override.rstrip("/")

    # ── Send pairing request ─────────────────────────────────────────────────
    banner("Pairing")
    p(f"  Sending POST to {primary_url}/api/node/pair …")

    try:
        code, resp = _post(
            f"{primary_url}/api/node/pair",
            payload={"my_url": my_url},
            headers={"Authorization": node_code},
            timeout=30,
        )
    except Exception as e:
        err(f"Could not reach {primary_url}: {e}")
        sys.exit(1)

    if code != 200:
        err(f"Pairing rejected (HTTP {code}): {resp.get('error', resp)}")
        sys.exit(1)

    shared_secret = resp.get("shared_secret")
    if not shared_secret:
        err("Primary node returned no shared_secret. Pairing incomplete.")
        sys.exit(1)

    ok(f"Paired! Shared secret: {shared_secret[:8]}…")

    # ── Save state ───────────────────────────────────────────────────────────
    state = {
        "primary_url":   primary_url,
        "my_url":        my_url,
        "shared_secret": shared_secret,
        "paired_at":     int(time.time()),
    }
    save_state(state)
    ok("State saved to .link_state.json")

    # ── LXD bootstrap ────────────────────────────────────────────────────────
    do_bootstrap = input("\n  Run LXD bootstrap now? (lxd init + image + ZFS pool) [Y/n]: ").strip().lower()
    if do_bootstrap in ("", "y", "yes"):
        lxd_bootstrap()
    else:
        warn("Skipped bootstrap. Run manually or VPS creation will fail on this node.")

    # ── Start stats loop ─────────────────────────────────────────────────────
    banner("Running")
    p("  Pairing complete. Starting background stats loop.")
    p("  Do NOT close this terminal (or use screen/tmux/systemd).")
    p("  Ctrl+C to stop.\n")
    stats_loop(primary_url, shared_secret, my_url)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n  Stopped.")
        sys.exit(0)
