"""
Multi-node mesh — with LXD bootstrap on pair.

When node B pairs with node A:
  1. POST /api/node/pair  (Authorization: <8-digit code>, body: {"my_url": "..."})
  2. Node A validates code, stores node B, returns shared_secret
  3. Node A immediately fires a bootstrap sequence ON NODE B via SSH-less subprocess:
       lxd init --auto
       lxc image copy ubuntu:22.04 local: --alias ubuntu/22.04
       lxc storage create zfs-new zfs size=6144GB
  3b. The bootstrap runs as a background thread — pairing response returns
      instantly, bootstrap logs are streamed to /api/node/bootstrap_status.

Overflow routing:
  - When this node hits MAX_VPS_PER_NODE the queue picks the least-loaded
    online peer and POSTs a VPS creation request to it via
    POST /api/node/create_vps  (Authorization: <shared_secret>)
  - The peer handles it locally and returns {container_id, ssh_url}.

Auth model:
  - 8-digit NODE_CODE: one-time pairing handshake, regenerates on restart.
  - shared_secret (32-byte hex): all ongoing mesh API calls.
  - Fail-open per peer.
"""

import os
import time
import secrets
import threading
import subprocess
import requests

MAX_VPS_PER_NODE = 150

NODE_CODE = f"{secrets.randbelow(100_000_000):08d}"

_detected_url: str = ""
_url_lock = threading.Lock()
NODE_PUBLIC_URL_OVERRIDE = os.environ.get("NODE_PUBLIC_URL", "").rstrip("/")
_MESH_TIMEOUT = 10  # seconds for cross-node VPS creation calls

# Bootstrap log buffer per peer URL
_bootstrap_logs: dict = {}
_bootstrap_lock = threading.Lock()


def get_node_url() -> str:
    if NODE_PUBLIC_URL_OVERRIDE:
        return NODE_PUBLIC_URL_OVERRIDE
    with _url_lock:
        return _detected_url


def set_detected_url(url: str):
    global _detected_url
    if NODE_PUBLIC_URL_OVERRIDE:
        return
    with _url_lock:
        if not _detected_url and url:
            _detected_url = url.rstrip("/")


# ---------------------------------------------------------------------------
# DB schema
# ---------------------------------------------------------------------------

def init_mesh_tables(db):
    db.executescript("""
    CREATE TABLE IF NOT EXISTS nodes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        url TEXT UNIQUE NOT NULL,
        shared_secret TEXT NOT NULL,
        label TEXT,
        connected_at INTEGER NOT NULL,
        last_seen INTEGER DEFAULT 0,
        vps_count INTEGER DEFAULT 0,
        cpu_cores INTEGER DEFAULT 0,
        ram_mb INTEGER DEFAULT 0,
        disk_gb INTEGER DEFAULT 0,
        bootstrapped INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );
    """)
    # migration for old DBs
    try:
        db.execute("ALTER TABLE nodes ADD COLUMN bootstrapped INTEGER DEFAULT 0")
    except Exception:
        pass
    db.commit()


def add_notification(db, message: str):
    db.execute(
        "INSERT INTO notifications(message, created_at) VALUES(?,?)",
        (message, int(time.time()))
    )
    db.commit()


# ---------------------------------------------------------------------------
# Bootstrap (runs on THIS machine after pairing to prepare it as a peer)
# ---------------------------------------------------------------------------

def _append_log(peer_url: str, line: str):
    with _bootstrap_lock:
        if peer_url not in _bootstrap_logs:
            _bootstrap_logs[peer_url] = []
        _bootstrap_logs[peer_url].append(line)


def get_bootstrap_logs(peer_url: str) -> list:
    with _bootstrap_lock:
        return list(_bootstrap_logs.get(peer_url, []))


def _run_bootstrap(peer_url: str, db_path: str):
    """
    Runs the three LXD setup commands needed to make this node ready to
    provision VPS containers.  Called as a daemon thread after pairing
    so the /api/node/pair response returns immediately.

    Commands (in order, matching what the user specified):
      1. lxd init --auto
      2. lxc image copy ubuntu:22.04 local: --alias ubuntu/22.04
      3. lxc storage create zfs-new zfs size=6144GB
    """
    steps = [
        ("lxd init --auto",
         ["lxd", "init", "--auto"]),
        ("lxc image copy ubuntu:22.04 local: --alias ubuntu/22.04",
         ["lxc", "image", "copy", "ubuntu:22.04", "local:",
          "--alias", "ubuntu/22.04"]),
        ("lxc storage create zfs-new zfs size=6144GB",
         ["lxc", "storage", "create", "zfs-new", "zfs", "size=6144GB"]),
    ]

    _append_log(peer_url, "[BOOTSTRAP] Starting LXD setup on this node...")

    for label, cmd in steps:
        _append_log(peer_url, f"[BOOTSTRAP] $ {label}")
        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=600
            )
            if result.stdout.strip():
                for line in result.stdout.strip().splitlines():
                    _append_log(peer_url, f"  {line}")
            if result.returncode != 0:
                err = result.stderr.strip() or "non-zero exit"
                _append_log(peer_url, f"[BOOTSTRAP] ERROR: {err}")
                # Continue anyway — storage pool may already exist etc.
            else:
                _append_log(peer_url, f"[BOOTSTRAP] ✓ Done.")
        except FileNotFoundError:
            _append_log(peer_url, f"[BOOTSTRAP] ERROR: command not found — is LXD installed?")
        except subprocess.TimeoutExpired:
            _append_log(peer_url, f"[BOOTSTRAP] ERROR: timed out after 600s")
        except Exception as e:
            _append_log(peer_url, f"[BOOTSTRAP] ERROR: {e}")

    _append_log(peer_url, "[BOOTSTRAP] Setup complete. Node is ready to provision VPSes.")

    # Mark bootstrapped in DB
    import sqlite3
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        conn.execute(
            "UPDATE nodes SET bootstrapped=1 WHERE url=?", (peer_url.rstrip("/"),)
        )
        conn.commit()
        conn.close()
    except Exception as e:
        _append_log(peer_url, f"[BOOTSTRAP] DB update failed: {e}")


def trigger_bootstrap(peer_url: str, db_path: str = "panel.db"):
    """Kicks off the LXD bootstrap in a daemon thread."""
    t = threading.Thread(
        target=_run_bootstrap, args=(peer_url, db_path), daemon=True
    )
    t.start()


# ---------------------------------------------------------------------------
# Pairing
# ---------------------------------------------------------------------------

def pair_with_node(db, remote_url: str, remote_code: str):
    """
    This node initiates pairing with remote_url.
    POST /api/node/pair  Authorization: <remote_code>  body: {"my_url": "..."}

    On success:
      - Stores remote_url + shared_secret locally.
      - Fires bootstrap thread to prepare THIS node as a mesh peer.
    """
    remote_url = remote_url.rstrip("/")
    my_url = get_node_url()

    if not my_url:
        return False, (
            "This node's public URL hasn't been detected yet. "
            "Make sure the panel is receiving real HTTP traffic, "
            "or set NODE_PUBLIC_URL environment variable."
        )

    try:
        resp = requests.post(
            f"{remote_url}/api/node/pair",
            json={"my_url": my_url},
            headers={"Authorization": remote_code},
            timeout=_MESH_TIMEOUT,
        )
    except Exception as e:
        return False, f"Could not reach {remote_url}: {e}"

    if resp.status_code != 200:
        try:
            err = resp.json().get("error", resp.text[:200])
        except Exception:
            err = resp.text[:200]
        return False, f"Pairing rejected: {err}"

    data = resp.json()
    shared_secret = data.get("shared_secret")
    if not shared_secret:
        return False, "Remote node accepted pairing but returned no shared secret."

    db.execute(
        "INSERT INTO nodes(url, shared_secret, connected_at, bootstrapped) VALUES(?,?,?,0) "
        "ON CONFLICT(url) DO UPDATE SET shared_secret=excluded.shared_secret, "
        "connected_at=excluded.connected_at, bootstrapped=0",
        (remote_url, shared_secret, int(time.time()))
    )
    add_notification(db, f"Node paired: {remote_url}")
    db.commit()

    # Bootstrap THIS node in background so it's ready to receive overflow VPSes
    trigger_bootstrap(remote_url)

    return True, f"Connected to {remote_url}. LXD bootstrap running in background."


def accept_pairing(db, submitted_code: str, requester_url: str):
    """
    Called when another node POSTs /api/node/pair to US.
    Validates 8-digit code, stores peer, returns shared_secret.
    Also triggers bootstrap on the requester (they handle it themselves after this).
    """
    if submitted_code != NODE_CODE:
        return False, "Incorrect node code."
    if not requester_url:
        return False, "Missing my_url in request body."

    shared_secret = secrets.token_hex(32)
    db.execute(
        "INSERT INTO nodes(url, shared_secret, connected_at, bootstrapped) VALUES(?,?,?,0) "
        "ON CONFLICT(url) DO UPDATE SET shared_secret=excluded.shared_secret, "
        "connected_at=excluded.connected_at",
        (requester_url.rstrip("/"), shared_secret, int(time.time()))
    )
    add_notification(db, f"Node paired: {requester_url.rstrip('/')}")
    db.commit()
    return True, shared_secret


def verify_peer_secret(db, peer_url: str, secret: str) -> bool:
    if not peer_url or not secret:
        return False
    row = db.execute(
        "SELECT shared_secret FROM nodes WHERE url=?", (peer_url.rstrip("/"),)
    ).fetchone()
    return bool(row and row["shared_secret"] == secret)


# ---------------------------------------------------------------------------
# Overflow VPS creation on peer node
# ---------------------------------------------------------------------------

def create_vps_on_peer(peer_url: str, shared_secret: str, my_url: str,
                        username: str, cpu: int, ram_mb: int, disk_gb: int) -> dict:
    """
    Asks a peer node to create a VPS on our behalf (overflow routing).
    POST /api/node/create_vps   Authorization: <shared_secret>
    Returns {"container_id": "...", "ssh_url": "..."} or {"error": "..."}.
    """
    try:
        resp = requests.post(
            f"{peer_url}/api/node/create_vps",
            json={
                "username":   username,
                "cpu":        cpu,
                "ram_mb":     ram_mb,
                "disk_gb":    disk_gb,
                "origin_url": my_url,
            },
            headers={
                "X-Node-Url":    my_url,
                "Authorization": shared_secret,
            },
            timeout=300,  # VPS creation can take a while
        )
        if resp.status_code == 200:
            return resp.json()
        try:
            return {"error": resp.json().get("error", resp.text[:200])}
        except Exception:
            return {"error": resp.text[:200]}
    except Exception as e:
        return {"error": str(e)}


def get_peer_for_overflow(db) -> tuple:
    """
    Returns (url, shared_secret) of the least-loaded online peer with capacity,
    or (None, None) if no peer is available.
    Online = last_seen within 120s.
    """
    cutoff = int(time.time()) - 120
    row = db.execute(
        "SELECT url, shared_secret FROM nodes "
        "WHERE last_seen > ? AND vps_count < ? "
        "ORDER BY vps_count ASC LIMIT 1",
        (cutoff, MAX_VPS_PER_NODE)
    ).fetchone()
    if row:
        return row["url"], row["shared_secret"]
    return None, None


# ---------------------------------------------------------------------------
# IP dedup across mesh
# ---------------------------------------------------------------------------

def check_ip_across_mesh(db, ip: str):
    my_url = get_node_url()
    for node in list_nodes(db):
        try:
            resp = requests.post(
                f"{node['url']}/api/node/check_ip",
                json={"ip": ip},
                headers={
                    "X-Node-Url":    my_url,
                    "Authorization": node["shared_secret"],
                },
                timeout=5,
            )
            if resp.status_code == 200 and resp.json().get("has_vps"):
                return True, node["url"]
        except Exception as e:
            print(f"[MESH] check_ip → {node['url']} failed (fail-open): {e}")
    return False, None


# ---------------------------------------------------------------------------
# Node listing + stats
# ---------------------------------------------------------------------------

def list_nodes(db):
    return db.execute("SELECT * FROM nodes ORDER BY vps_count ASC").fetchall()


def push_stats_to_peers(db, vps_count: int, cpu_cores: int, ram_mb: int, disk_gb: int):
    my_url = get_node_url()
    if not my_url:
        return
    payload = {
        "vps_count": vps_count,
        "cpu_cores": cpu_cores,
        "ram_mb":    ram_mb,
        "disk_gb":   disk_gb,
    }
    for node in list_nodes(db):
        try:
            requests.post(
                f"{node['url']}/api/node/stats",
                json=payload,
                headers={
                    "X-Node-Url":    my_url,
                    "Authorization": node["shared_secret"],
                },
                timeout=5,
            )
        except Exception:
            pass


def update_peer_stats(db, peer_url: str, vps_count: int,
                      cpu_cores: int, ram_mb: int, disk_gb: int):
    db.execute(
        "UPDATE nodes SET last_seen=?, vps_count=?, cpu_cores=?, ram_mb=?, disk_gb=? "
        "WHERE url=?",
        (int(time.time()), vps_count, cpu_cores, ram_mb, disk_gb, peer_url.rstrip("/"))
    )
    db.commit()
