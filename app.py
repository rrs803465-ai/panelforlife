"""
LXD container management — rewritten.

Changes from v1:
  - Port forwarding completely removed.
  - Per-VPS resource limits are read from panel_config (set in setup.py)
    rather than being hardcoded constants.
  - File manager helpers: list_files(), upload_file(), delete_file(),
    download_file(), create_dir() — all exec into the container.
  - Terminal websocket helper: exec_stream() for xterm.js integration.
  - sshx session URL is still generated and stored for browser terminal
    fallback and the new embedded terminal.
"""

import os
import re
import time
import shutil
import sqlite3
import secrets
import string
import base64

from pylxd import Client
from pylxd.exceptions import LXDAPIException, NotFound as LXDNotFound

# ── regexes ────────────────────────────────────────────────────────────────
SSHX_LINK_RE  = re.compile(r"https://sshx\.io/s/[A-Za-z0-9]+#[A-Za-z0-9_-]+")
ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")

client = Client()

IMAGE_ALIAS  = os.environ.get("VPS_IMAGE_ALIAS",  "ubuntu/22.04")
STORAGE_POOL = os.environ.get("VPS_STORAGE_POOL", "zfs-new")
DB           = "panel.db"

MAX_VPS_PER_NODE  = 150
TOTAL_DISK_BUDGET_GB = 6 * 1024   # 6 TB panel-wide ceiling
MIN_FREE_DISK_GB  = 100


# ── KVM availability detection ──────────────────────────────────────────────
# Checked once at import time so every call to kvm_available() is free.
# /dev/kvm is the definitive signal — if it's absent the kernel doesn't
# expose hardware virtualisation to userspace and there's nothing to offer.
import subprocess as _subprocess

def _probe_kvm() -> bool:
    """Live probe — called each time so late LXD startup or module load is detected."""
    if not os.path.exists("/dev/kvm"):
        return False
    try:
        out = _subprocess.run(
            ["lsmod"], capture_output=True, text=True, timeout=4
        ).stdout
        return "kvm" in out.lower()
    except Exception:
        return True   # lsmod unavailable — trust /dev/kvm presence


def kvm_available() -> bool:
    """Returns True if /dev/kvm exists and the kvm kernel module is loaded.
    Re-probes every call so a late LXD start or module load is picked up.
    """
    return _probe_kvm()


# ── config helpers ──────────────────────────────────────────────────────────

def _get_config(key: str, default: str) -> str:
    try:
        db = sqlite3.connect(DB)
        row = db.execute(
            "SELECT value FROM panel_config WHERE key=?", (key,)
        ).fetchone()
        db.close()
        return row[0] if row else default
    except Exception:
        return default


def get_free_vps_cpu()  -> int:  return int(_get_config("vps_cpu_cores", "4"))
def get_free_vps_ram()  -> int:  return int(_get_config("vps_ram_gb",    "4")) * 1024   # → MB
def get_free_vps_disk() -> int:  return int(_get_config("vps_disk_gb",   "80"))


# ── capacity ────────────────────────────────────────────────────────────────

def get_host_capacity() -> dict:
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

    real_disk_gb = None
    try:
        usage = shutil.disk_usage("/")
        real_disk_gb = usage.total // (1024 ** 3)
    except Exception:
        pass

    return {
        "cpu_cores":        cpu_cores,
        "ram_mb":           ram_mb,
        "disk_budget_gb":   TOTAL_DISK_BUDGET_GB,
        "disk_allocated_gb": get_allocated_disk_gb(),
        "real_disk_gb":     real_disk_gb,
    }


def _quota_gb(inst) -> int:
    try:
        size = inst.devices.get("root", {}).get("size", "")
        if size.upper().endswith("GB"):
            return int(size[:-2])
        if size.upper().endswith("TB"):
            return int(size[:-2]) * 1024
    except Exception:
        pass
    return 0


def get_allocated_disk_gb() -> int:
    total = 0
    for inst in client.instances.all():
        if not inst.name.startswith("vps-"):
            continue
        usage = None
        try:
            state   = inst.state()
            usage   = (state.disk or {}).get("root", {}).get("usage")
        except Exception:
            pass
        total += usage if usage else _quota_gb(inst) * (1024 ** 3)
    return total // (1024 ** 3)


def can_allocate_disk(additional_gb: int):
    allocated   = get_allocated_disk_gb()
    budget_ok   = (allocated + additional_gb) <= TOTAL_DISK_BUDGET_GB

    real_free_gb = None
    try:
        usage        = shutil.disk_usage("/")
        real_free_gb = usage.free // (1024 ** 3)
    except Exception:
        pass

    safety_ok = real_free_gb is None or real_free_gb >= MIN_FREE_DISK_GB

    if not safety_ok:
        return False, allocated, TOTAL_DISK_BUDGET_GB, (
            f"Only {real_free_gb}GB free on disk (keeping {MIN_FREE_DISK_GB}GB reserve)."
        )
    if not budget_ok:
        return False, allocated, TOTAL_DISK_BUDGET_GB, None
    return True, allocated, TOTAL_DISK_BUDGET_GB, None


def count_all_vps() -> int:
    return sum(1 for inst in client.instances.all() if inst.name.startswith("vps-"))


def can_create_vps():
    current = count_all_vps()
    return current < MAX_VPS_PER_NODE, current


# ── low-level helpers ───────────────────────────────────────────────────────

def _get_container(container_id: str):
    try:
        return client.instances.get(container_id)
    except (LXDNotFound, Exception):
        return None


def _exec(inst, cmd_list: list, environment: dict = None):
    return inst.execute(cmd_list, environment=environment or {})


def _wait_running(inst, timeout: int = 30) -> bool:
    for _ in range(timeout):
        inst.sync()
        if inst.status.lower() == "running":
            return True
        time.sleep(1)
    return False


def _set_root_password_with_retry(inst, password: str, attempts: int = 15, delay: int = 2):
    for _ in range(attempts):
        try:
            _exec(inst, ["bash", "-c", f"echo root:{password} | chpasswd"])
            return
        except Exception as e:
            time.sleep(delay)


def generate_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ── container lifecycle ─────────────────────────────────────────────────────

def _create_raw(username: str, cpu: int, ram_mb: int, disk_gb: int, image: str = IMAGE_ALIAS) -> dict:
    password       = generate_password()
    container_name = f"vps-{username}-{secrets.token_hex(3)}"

    config = {
        "name":   container_name,
        "source": {"type": "image", "alias": image},
        "config": {
            "limits.cpu":                            str(cpu),
            "limits.memory":                         f"{ram_mb}MB",
            "limits.memory.enforce":                 "hard",
            "security.nesting":                      "true",
            "security.privileged":                   "true",
            "security.syscalls.intercept.mknod":     "true",
            "security.syscalls.intercept.setxattr":  "true",
            "linux.kernel_modules":                  "overlay,br_netfilter",
        },
        "devices": {
            "root": {
                "path": "/",
                "pool": STORAGE_POOL,
                "type": "disk",
                "size": f"{disk_gb}GB",
            }
        },
    }

    try:
        inst = client.instances.create(config, wait=True)
        inst.start(wait=True)
        if not _wait_running(inst):
            raise RuntimeError("Container did not reach running state in time")
        _set_root_password_with_retry(inst, password)
        return {"container_id": container_name, "password": password, "status": "running"}
    except LXDAPIException as e:
        return {"error": str(e)}
    except Exception as e:
        return {"error": str(e)}


def _enable_kvm_on_container(inst) -> bool:
    """
    Grants a container access to /dev/kvm.
    Uses lxc CLI directly (same approach as hvm.py) rather than pylxd
    config mutation to avoid pylxd .save() quirks with raw.lxc and devices.

    Steps (matching hvm.py):
      1. lxc config set <name> security.nesting true
      2. lxc config set <name> raw.lxc 'lxc.cgroup2.devices.allow = c 10:232 rwm'
      3. lxc config device add <name> kvm unix-char path=/dev/kvm
    """
    if not _probe_kvm():
        return False
    name = inst.name
    try:
        # 1. Enable nesting
        r1 = _subprocess.run(
            ["lxc", "config", "set", name, "security.nesting", "true"],
            capture_output=True, text=True, timeout=30
        )
        if r1.returncode != 0:
            print(f"[KVM] nesting set failed on {name}: {r1.stderr.strip()}")

        # 2. cgroup2 allow rule — read current raw.lxc first, append only if missing
        inst.sync()
        existing = inst.config.get("raw.lxc", "")
        rule = "lxc.cgroup2.devices.allow = c 10:232 rwm"
        if rule not in existing:
            new_raw = (existing.rstrip() + "\n" + rule).strip() if existing else rule
            r2 = _subprocess.run(
                ["lxc", "config", "set", name, "raw.lxc", new_raw],
                capture_output=True, text=True, timeout=30
            )
            if r2.returncode != 0:
                print(f"[KVM] raw.lxc set failed on {name}: {r2.stderr.strip()}")

        # 3. Add /dev/kvm device
        r3 = _subprocess.run(
            ["lxc", "config", "device", "add", name,
             "kvm", "unix-char", "path=/dev/kvm"],
            capture_output=True, text=True, timeout=30
        )
        if r3.returncode != 0 and "already exists" not in r3.stderr:
            print(f"[KVM] device add failed on {name}: {r3.stderr.strip()}")
            return False

        print(f"[KVM] /dev/kvm attached to {name}")
        return True
    except Exception as e:
        print(f"[KVM] _enable failed on {name}: {e}")
        return False


def _disable_kvm_on_container(inst) -> bool:
    """Removes /dev/kvm device and cgroup rule via lxc CLI."""
    name = inst.name
    try:
        # Remove device (ignore error if it doesn't exist)
        _subprocess.run(
            ["lxc", "config", "device", "remove", name, "kvm"],
            capture_output=True, text=True, timeout=30
        )
        # Clean cgroup rule from raw.lxc
        inst.sync()
        existing = inst.config.get("raw.lxc", "")
        rule = "lxc.cgroup2.devices.allow = c 10:232 rwm"
        cleaned = "\n".join(
            ln for ln in existing.splitlines() if ln.strip() != rule
        ).strip()
        if cleaned != existing.strip():
            _subprocess.run(
                ["lxc", "config", "set", name, "raw.lxc", cleaned],
                capture_output=True, text=True, timeout=30
            )
        print(f"[KVM] /dev/kvm detached from {name}")
        return True
    except Exception as e:
        print(f"[KVM] _disable failed on {name}: {e}")
        return False


def set_kvm_enabled(container_id: str, enable: bool) -> bool:
    """
    Toggles KVM access on a running or stopped container.
    Called from app.py admin grant-vps / admin vps edit flows.
    Returns True on success.
    """
    inst = _get_container(container_id)
    if not inst:
        return False
    if enable:
        return _enable_kvm_on_container(inst)
    return _disable_kvm_on_container(inst)


def create_vps_container(
    username: str,
    cpu_limit:    int = None,
    ram_limit_mb: int = None,
    disk_limit_gb: int = None,
    image: str = IMAGE_ALIAS,
    kvm_enabled: bool = False,
):
    """
    High-level entry point used by app.py.
    Falls back to panel_config limits when individual params are None.
    kvm_enabled is only honoured when kvm_available() returns True —
    silently ignored otherwise so the rest of provisioning proceeds.
    Returns (container_id, sshx_session_url).
    Raises RuntimeError on any failure.
    """
    cpu  = cpu_limit    if cpu_limit    is not None else get_free_vps_cpu()
    ram  = ram_limit_mb if ram_limit_mb is not None else get_free_vps_ram()
    disk = disk_limit_gb if disk_limit_gb is not None else get_free_vps_disk()

    allowed, current = can_create_vps()
    if not allowed:
        raise RuntimeError(
            f"Node VPS limit reached ({current}/{MAX_VPS_PER_NODE}). "
            "No new VPS can be created until existing ones are deleted."
        )

    result = _create_raw(username, cpu, ram, disk, image)
    if "error" in result:
        raise RuntimeError(result["error"])

    inst = _get_container(result["container_id"])

    # KVM — attach /dev/kvm before sshx so the device is present at first boot
    if kvm_enabled and _KVM_AVAILABLE:
        ok = _enable_kvm_on_container(inst)
        if not ok:
            print(f"[KVM] Warning: KVM requested but could not be attached to {result['container_id']}")

    # Install sshx (3 attempts)
    sshx_ready = any(_install_sshx(inst) or time.sleep(5) for _ in range(3))
    if not sshx_ready:
        raise RuntimeError("Could not install sshx after 3 attempts")

    # Start sshx session (3 attempts)
    session_url = None
    for _ in range(3):
        session_url = _start_sshx_session(inst)
        if session_url:
            break
        time.sleep(3)

    if not session_url:
        raise RuntimeError("sshx installed but session could not be established")

    return result["container_id"], session_url


def get_vps_specs(container_id: str) -> dict | None:
    inst = _get_container(container_id)
    if not inst:
        return None
    try:
        cpu  = int(inst.config.get("limits.cpu", "4"))
    except Exception:
        cpu  = 4
    ram_raw = inst.config.get("limits.memory", f"{get_free_vps_ram()}MB")
    try:
        num = int("".join(c for c in ram_raw if c.isdigit()) or 0)
        ram = num  # already in MB
    except Exception:
        ram = get_free_vps_ram()
    disk = _quota_gb(inst) or get_free_vps_disk()
    return {"cpu_cores": cpu, "ram_mb": ram, "disk_gb": disk}


def reinstall_vps(container_id: str, username: str, kvm_enabled: bool = False):
    specs = get_vps_specs(container_id) or {
        "cpu_cores": get_free_vps_cpu(),
        "ram_mb":    get_free_vps_ram(),
        "disk_gb":   get_free_vps_disk(),
    }
    try:
        destroy_vps(container_id)
    except Exception:
        pass
    return create_vps_container(
        username,
        cpu_limit=specs["cpu_cores"],
        ram_limit_mb=specs["ram_mb"],
        disk_limit_gb=specs["disk_gb"],
        kvm_enabled=kvm_enabled,
    )


def destroy_vps(container_id: str) -> dict:
    inst = _get_container(container_id)
    if not inst:
        return {"error": "not found"}
    try:
        if inst.status.lower() == "running":
            inst.stop(wait=True, timeout=10)
    except Exception:
        pass
    inst.delete(wait=True)
    return {"status": "deleted"}


def start_vps(container_id: str) -> dict:
    inst = _get_container(container_id)
    if not inst:
        return {"error": "not found"}
    inst.start(wait=True)
    return {"status": "started"}


def stop_vps(container_id: str) -> dict:
    inst = _get_container(container_id)
    if not inst:
        return {"error": "not found"}
    inst.stop(wait=True, timeout=10)
    return {"status": "stopped"}


def suspend_vps(container_id: str) -> dict:
    inst = _get_container(container_id)
    if not inst:
        return {"error": "not found"}
    try:
        inst.freeze(wait=True)
    except Exception:
        inst.stop(wait=True, timeout=10)
    return {"status": "suspended"}


def unsuspend_vps(container_id: str) -> dict:
    inst = _get_container(container_id)
    if not inst:
        return {"error": "not found"}
    inst.sync()
    try:
        if inst.status.lower() == "frozen":
            inst.unfreeze(wait=True)
        else:
            inst.start(wait=True)
    except Exception as e:
        return {"error": str(e)}
    return {"status": "running"}


def get_vps_status(container_id: str) -> dict:
    inst = _get_container(container_id)
    if not inst:
        return {"status": "not_found"}
    inst.sync()
    return {"status": inst.status.lower(), "name": inst.name}


def sync_status(container_id: str, db_status: str) -> str:
    if db_status not in ("running", "stopped"):
        return db_status
    real = get_vps_status(container_id).get("status", db_status)
    return real if real in ("running", "stopped") else db_status


# ── sshx ───────────────────────────────────────────────────────────────────

def _install_sshx(inst) -> bool:
    env = {"HOME": "/root", "DEBIAN_FRONTEND": "noninteractive"}
    find_cmd = (
        "command -v sshx || "
        "for p in /root/.local/bin/sshx /usr/local/bin/sshx /usr/bin/sshx; do "
        "  [ -x \"$p\" ] && echo \"$p\" && break; done"
    )
    try:
        check = _exec(inst, ["bash", "-c", find_cmd], environment=env)
        found = (check.stdout or "").strip()
        if found:
            _ensure_symlinked(inst, found, env)
            return True

        curl_ok = _exec(inst, ["bash", "-c", "command -v curl"], environment=env)
        if not (curl_ok.stdout or "").strip():
            if not _apt_install_with_retry(inst, "curl", env):
                return False

        install_cmd = (
            "curl --retry 3 --retry-delay 2 --retry-connrefused "
            "--connect-timeout 10 -sSf https://sshx.io/get | sh"
        )
        for attempt in range(3):
            result = _exec(inst, ["bash", "-c", install_cmd], environment=env)
            if result.exit_code == 0:
                break
            time.sleep(2)

        check2 = _exec(inst, ["bash", "-c", find_cmd], environment=env)
        found  = (check2.stdout or "").strip()
        if not found:
            return False
        _ensure_symlinked(inst, found, env)
        return True
    except Exception as e:
        print(f"[sshx install] {e}")
        return False


def _ensure_symlinked(inst, found_path: str, env: dict):
    if found_path == "/usr/local/bin/sshx":
        return
    try:
        _exec(inst, ["bash", "-c", f"ln -sf '{found_path}' /usr/local/bin/sshx"], environment=env)
    except Exception:
        pass


def _apt_install_with_retry(inst, package: str, env: dict, attempts: int = 5) -> bool:
    wait_lock = (
        "for i in $(seq 1 30); do "
        "  fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || break; sleep 1; done"
    )
    for _ in range(attempts):
        _exec(inst, ["bash", "-c", wait_lock], environment=env)
        result = _exec(
            inst, ["bash", "-c", f"apt-get update -qq && apt-get install -y -qq {package}"],
            environment=env,
        )
        if result.exit_code == 0:
            return True
        time.sleep(4)
    return False


def _start_sshx_session(inst) -> str | None:
    try:
        _exec(inst, ["bash", "-c", "pkill sshx 2>/dev/null; rm -f /tmp/sshx.log; true"])
        _exec(inst, ["bash", "-c",
                     "NO_COLOR=1 TERM=dumb nohup sshx > /tmp/sshx.log 2>&1 < /dev/null & disown"])
        for _ in range(10):
            time.sleep(1)
            result    = _exec(inst, ["bash", "-c", "cat /tmp/sshx.log 2>/dev/null || true"])
            clean_log = ANSI_ESCAPE_RE.sub("", result.stdout or "")
            match     = SSHX_LINK_RE.search(clean_log)
            if match:
                return match.group(0)
        return None
    except Exception as e:
        print(f"[sshx session] {e}")
        return None


def regen_sshx(container_id: str) -> str | None:
    inst = _get_container(container_id)
    if not inst:
        raise RuntimeError("Container not found")
    return _start_sshx_session(inst)


# ── stats ───────────────────────────────────────────────────────────────────

_cpu_sample_cache: dict = {}


def get_container_stats(container_id: str, created_at: int = None) -> dict:
    inst = _get_container(container_id)
    if not inst:
        raise RuntimeError("Container not found")

    inst.sync()
    raw = inst.state()

    mem_usage       = raw.memory.get("usage", 0) if raw.memory else 0
    mem_limit_bytes = 0
    try:
        cfg = inst.config.get("limits.memory", "0MB")
        num = int("".join(c for c in cfg if c.isdigit()) or 0)
        mem_limit_bytes = num * 1024 * 1024
    except Exception:
        pass

    try:
        num_cpus = int(inst.config.get("limits.cpu", "1"))
    except Exception:
        num_cpus = 1

    cpu_ns_now = raw.cpu.get("usage", 0) if raw.cpu else 0
    t_now      = time.time()
    cpu_pct    = 0.0
    prev       = _cpu_sample_cache.get(container_id)
    if prev:
        cpu_ns_prev, t_prev = prev
        elapsed_ns          = (t_now - t_prev) * 1e9
        cpu_delta_ns        = cpu_ns_now - cpu_ns_prev
        if elapsed_ns > 0 and cpu_delta_ns >= 0:
            cpu_pct = (cpu_delta_ns / (elapsed_ns * num_cpus)) * 100.0

    _cpu_sample_cache[container_id] = (cpu_ns_now, t_now)
    mem_pct    = (mem_usage / mem_limit_bytes * 100.0) if mem_limit_bytes else 0.0
    uptime_sec = int(time.time() - created_at) if created_at else None

    return {
        "cpu_percent":   round(cpu_pct, 2),
        "mem_usage_mb":  round(mem_usage / (1024 * 1024), 1),
        "mem_limit_mb":  round(mem_limit_bytes / (1024 * 1024), 1),
        "mem_percent":   round(mem_pct, 2),
        "uptime_seconds": uptime_sec,
    }


# ── mining detection ────────────────────────────────────────────────────────

_SAFE_PROCS = [
    "sshx", "sshd", "systemd", "systemd-journald", "systemd-logind",
    "apt", "apt-get", "dpkg", "unattended-upgrade", "cron", "bash",
    "python3", "app.py", "monitor.py", "vps.py", "gunicorn", "flask",
    "init", "dbus-daemon", "rsyslogd", "networkd-dispatcher",
]

_MINER_SIGS = [
    "xmrig", "xmr-stak", "cpuminer", "minerd", "cryptonight",
    "nicehash", "ethminer", "t-rex", "lolminer", "phoenixminer",
    "srbminer", "teamredminer", "unmineable", "kdevtmpfsi", "kinsing",
]

_MINER_PORTS = ["3333", "4444", "5555", "7777", "8080", "9999", "14444", "45700"]

_MINER_CMDS = [
    "--donate-level", "--cpu-priority", "-o stratum+tcp", "stratum+tcp://",
    "stratum+ssl://", "--algo=", "-a randomx", "-a rx/0", "--coin=monero",
    "--pool=", "-o pool.", "xmrig -o", "xmrig --url",
]


def check_for_mining(container_id: str) -> dict:
    inst = _get_container(container_id)
    if not inst:
        return {"suspected": False, "confidence": "low", "reasons": ["not found"], "raw": {}}

    weak, raw = [], {}

    try:
        result = _exec(inst, ["bash", "-c", "ps aux"])
        ps     = result.stdout or ""
        raw["ps"] = ps[:2000]
        for line in ps.lower().splitlines():
            if any(s in line for s in _SAFE_PROCS):
                continue
            for sig in _MINER_SIGS:
                if sig in line:
                    weak.append(f"process: '{sig}'")
    except Exception as e:
        raw["ps_error"] = str(e)

    try:
        result    = _exec(inst, ["bash", "-c", "ss -tnp 2>/dev/null || netstat -tnp 2>/dev/null"])
        conns     = result.stdout or ""
        raw["conns"] = conns[:2000]
        for port in _MINER_PORTS:
            if f":{port}" in conns:
                weak.append(f"connection on mining port {port}")
    except Exception as e:
        raw["conns_error"] = str(e)

    strong = []
    try:
        result   = _exec(inst, ["bash", "-c",
                                 "cat /root/.bash_history 2>/dev/null; "
                                 "ps -eo args --no-headers 2>/dev/null"])
        history  = (result.stdout or "").lower()
        for pattern in _MINER_CMDS:
            if pattern.lower() in history:
                strong.append(f"activation command: '{pattern}'")
    except Exception:
        pass

    if strong:
        return {"suspected": True,  "confidence": "high", "reasons": strong, "raw": raw}
    if len(weak) >= 2:
        return {"suspected": True,  "confidence": "low",  "reasons": weak,   "raw": raw}
    return      {"suspected": False, "confidence": "low",  "reasons": weak,   "raw": raw}


def handle_high_cpu(container_id: str, threshold: float = 90.0) -> dict:
    try:
        stats = get_container_stats(container_id)
    except Exception:
        return {"action": "none", "cpu_percent": 0.0}

    if stats["cpu_percent"] < threshold:
        return {"action": "none", "cpu_percent": stats["cpu_percent"]}

    mining = check_for_mining(container_id)
    if mining["suspected"] and mining["confidence"] == "high":
        suspend_vps(container_id)
        return {
            "action":         "suspended",
            "cpu_percent":    stats["cpu_percent"],
            "confidence":     "high",
            "reasons":        mining["reasons"],
        }
    if mining["suspected"]:
        return {
            "action":         "flagged_for_review",
            "cpu_percent":    stats["cpu_percent"],
            "confidence":     "low",
            "reasons":        mining["reasons"],
        }
    return {
        "action":      "none",
        "cpu_percent": stats["cpu_percent"],
        "note":        "high CPU, no mining evidence",
    }


# ── file manager ────────────────────────────────────────────────────────────

def list_files(container_id: str, path: str = "/root") -> list[dict]:
    """Returns a list of file/dir entries at the given path inside the container."""
    inst = _get_container(container_id)
    if not inst:
        raise RuntimeError("Container not found")

    # Use stat for a reliable machine-parseable listing
    cmd = (
        f"ls -la --time-style=+%s {path} 2>&1 | tail -n +2"
    )
    result = _exec(inst, ["bash", "-c", cmd])
    lines  = (result.stdout or "").strip().splitlines()
    entries = []
    for line in lines:
        parts = line.split(None, 8)
        if len(parts) < 9:
            continue
        perms, _, _, _, size_raw, _, _, _, name = parts
        if name in (".", ".."):
            continue
        is_dir  = perms.startswith("d")
        is_link = perms.startswith("l")
        try:
            size = int(size_raw)
        except ValueError:
            size = 0
        entries.append({
            "name":    name,
            "type":    "dir" if is_dir else ("link" if is_link else "file"),
            "size":    size,
            "perms":   perms,
        })
    return entries


def read_file_b64(container_id: str, path: str) -> str:
    """Returns file contents as a base64 string (safe for JSON transport)."""
    inst = _get_container(container_id)
    if not inst:
        raise RuntimeError("Container not found")
    result = _exec(inst, ["bash", "-c", f"base64 -w0 {path} 2>&1"])
    if result.exit_code != 0:
        raise RuntimeError(result.stdout or "Read failed")
    return (result.stdout or "").strip()


def write_file_b64(container_id: str, path: str, b64_content: str):
    """Writes base64-encoded content to a file inside the container."""
    inst = _get_container(container_id)
    if not inst:
        raise RuntimeError("Container not found")
    # Pipe through base64 decode — avoids shell escaping the raw content
    cmd = f"echo '{b64_content}' | base64 -d > {path}"
    result = _exec(inst, ["bash", "-c", cmd])
    if result.exit_code != 0:
        raise RuntimeError(result.stdout or "Write failed")


def delete_file(container_id: str, path: str):
    """Deletes a file or directory (recursive) inside the container."""
    inst = _get_container(container_id)
    if not inst:
        raise RuntimeError("Container not found")
    # Refuse to delete root or anything dangerous
    dangerous = ["/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/proc", "/sys"]
    if path.rstrip("/") in dangerous:
        raise RuntimeError("Refusing to delete protected path")
    result = _exec(inst, ["bash", "-c", f"rm -rf {path}"])
    if result.exit_code != 0:
        raise RuntimeError(result.stdout or "Delete failed")


def create_directory(container_id: str, path: str):
    """Creates a directory inside the container."""
    inst = _get_container(container_id)
    if not inst:
        raise RuntimeError("Container not found")
    result = _exec(inst, ["bash", "-c", f"mkdir -p {path}"])
    if result.exit_code != 0:
        raise RuntimeError(result.stdout or "mkdir failed")


def exec_command(container_id: str, cmd: str) -> dict:
    """Runs a one-shot command, returns exit_code + combined output."""
    inst = _get_container(container_id)
    if not inst:
        return {"error": "not found"}
    result = _exec(inst, ["bash", "-c", cmd])
    return {
        "exit_code": result.exit_code,
        "output":    (result.stdout or "") + (result.stderr or ""),
    }


# ── build log stream ────────────────────────────────────────────────────────

def build_logs_stream(container_id: str):
    inst = _get_container(container_id)
    if not inst:
        yield "Container not found"
        return
    try:
        result = _exec(inst, ["bash", "-c",
                               "tail -n 100 /var/log/syslog 2>/dev/null || echo 'no logs yet'"])
        for line in (result.stdout or "").splitlines():
            yield line
    except Exception as e:
        yield f"Could not read logs: {e}"
