"""
Panel4Life — rewritten app.py

New features vs v1:
  1. In-browser terminal via exec_command polling + WebSocket-compatible
     /vps/<id>/terminal/exec endpoint (works alongside sshx).
  2. File manager — list/upload/download/delete/mkdir per VPS.
  3. Node auto-URL detection — no manual NODE_PUBLIC_URL required.
  4. Cascading node routing — when this node hits 150 VPSes, redirect
     the creation request to the least-loaded available peer node.
  5. Per-VPS resource limits read from panel_config (set in setup.py).
  6. Node stats push / nodes admin tab shows live peer stats + online status.
  7. YouTube-verified badge (carried over, cleaned up).
  + Port forwarding completely removed.
  + GET-based inter-node calls replaced with POST + Authorization header.
"""

import os
import sqlite3
import time
import secrets
import threading
import base64
from datetime import timedelta

from flask import (
    Flask, request, render_template, redirect, url_for,
    jsonify, session, Response, stream_with_context,
    send_from_directory, flash, abort
)
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.middleware.proxy_fix import ProxyFix

from vps import (
    create_vps_container, destroy_vps, suspend_vps, unsuspend_vps,
    regen_sshx, get_container_stats, build_logs_stream,
    can_create_vps, can_allocate_disk, MAX_VPS_PER_NODE,
    get_host_capacity, start_vps, stop_vps, reinstall_vps,
    get_vps_status, sync_status,
    list_files, read_file_b64, write_file_b64,
    delete_file, create_directory, exec_command,
    get_free_vps_cpu, get_free_vps_ram, get_free_vps_disk,
    kvm_available, set_kvm_enabled,
)
from monitor import start_monitor
import queue_manager as queue
import node_mesh
import ip_intel

# ── Flask setup ─────────────────────────────────────────────────────────────

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

SECRET_KEY_FILE = "secret.key"
if os.environ.get("FLASK_SECRET_KEY"):
    app.secret_key = os.environ["FLASK_SECRET_KEY"]
elif os.path.exists(SECRET_KEY_FILE):
    with open(SECRET_KEY_FILE) as f:
        app.secret_key = f.read().strip()
else:
    _key = secrets.token_hex(32)
    with open(SECRET_KEY_FILE, "w") as f:
        f.write(_key)
    app.secret_key = _key

app.config["REMEMBER_COOKIE_DURATION"] = timedelta(days=30)

DB = "panel.db"
login_manager = LoginManager(app)
login_manager.login_view = "login"

# Admin-granted VPS hard ceilings
ADMIN_MAX_RAM_GB    = 160
ADMIN_MAX_CPU_CORES = 20
ADMIN_MAX_DISK_GB   = 500

# Debounce maps (in-process — fine for single-worker gunicorn)
_last_create_click: dict = {}
_last_power_action: dict = {}
CREATE_DEBOUNCE_SECONDS   = 10
POWER_DEBOUNCE_SECONDS    = 10
REINSTALL_DEBOUNCE_SECONDS = 60


# ── DB helpers ───────────────────────────────────────────────────────────────

def get_db():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return db


def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        signup_ip TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0,
        created_at INTEGER NOT NULL,
        recovery_code_hash TEXT,
        recovery_code_shown INTEGER DEFAULT 0,
        youtube_verified INTEGER DEFAULT 0,
        is_vpn_signup INTEGER DEFAULT 0,
        vpn_provider TEXT
    );
    CREATE TABLE IF NOT EXISTS vps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        container_id TEXT NOT NULL,
        ssh_command TEXT,
        status TEXT DEFAULT 'creating',
        creator_ip TEXT NOT NULL,
        created_at INTEGER NOT NULL,
        last_regen INTEGER DEFAULT 0,
        node_id INTEGER DEFAULT 0,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        stars INTEGER NOT NULL,
        comment TEXT,
        created_at INTEGER NOT NULL,
        FOREIGN KEY(user_id) REFERENCES users(id)
    );
    CREATE TABLE IF NOT EXISTS broadcast (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        message TEXT,
        active INTEGER DEFAULT 0,
        updated_at INTEGER
    );
    CREATE TABLE IF NOT EXISTS panel_config (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    """)
    db.execute("INSERT OR IGNORE INTO broadcast(id,message,active,updated_at) VALUES(1,'',0,0)")

    # Best-effort column migrations for older DBs
    for stmt in [
        "ALTER TABLE users ADD COLUMN is_vpn_signup INTEGER DEFAULT 0",
        "ALTER TABLE users ADD COLUMN vpn_provider TEXT",
        "ALTER TABLE users ADD COLUMN youtube_verified INTEGER DEFAULT 0",
        "ALTER TABLE vps ADD COLUMN node_id INTEGER DEFAULT 0",
        "ALTER TABLE vps ADD COLUMN kvm_enabled INTEGER DEFAULT 0",
    ]:
        try:
            db.execute(stmt)
        except sqlite3.OperationalError:
            pass

    # Drop old UNIQUE constraint on vps.user_id if present
    row = db.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='vps'").fetchone()
    if row and row["sql"] and "UNIQUE" in row["sql"].upper():
        db.executescript("""
        ALTER TABLE vps RENAME TO vps_old;
        CREATE TABLE vps (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            container_id TEXT NOT NULL,
            ssh_command TEXT,
            status TEXT DEFAULT 'creating',
            creator_ip TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            last_regen INTEGER DEFAULT 0,
            node_id INTEGER DEFAULT 0,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        INSERT INTO vps SELECT id,user_id,container_id,ssh_command,status,
                               creator_ip,created_at,last_regen,0 FROM vps_old;
        DROP TABLE vps_old;
        """)

    db.commit()
    node_mesh.init_mesh_tables(db)
    db.close()


# ── URL auto-detection ───────────────────────────────────────────────────────

@app.before_request
def detect_node_url():
    """Latches this node's public URL from the first real incoming request."""
    host  = request.host          # e.g. "panel.example.com" or "1.2.3.4:5000"
    proto = request.scheme        # "http" or "https"
    node_mesh.set_detected_url(f"{proto}://{host}")


# ── Context processors ───────────────────────────────────────────────────────

@app.context_processor
def inject_globals():
    db  = get_db()
    row = db.execute("SELECT message, active FROM broadcast WHERE id=1").fetchone()
    db.close()
    return dict(
        broadcast_message=(
            row["message"] if row and row["active"] and row["message"] else None
        ),
        node_url=node_mesh.get_node_url(),
        node_code=node_mesh.NODE_CODE,
        kvm_available=kvm_available(),   # Templates use this to show/hide KVM option
    )


# ── Auth ─────────────────────────────────────────────────────────────────────

class User(UserMixin):
    def __init__(self, row):
        self.id               = row["id"]
        self.username         = row["username"]
        self.is_admin         = bool(row["is_admin"])
        self.youtube_verified = bool(row["youtube_verified"]) if row["youtube_verified"] is not None else False


@login_manager.user_loader
def load_user(uid):
    row = get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return User(row) if row else None


def generate_recovery_code(length: int = 6) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ── Static / landing ─────────────────────────────────────────────────────────

@app.route("/bg/<path:filename>")
def serve_background(filename):
    return send_from_directory("templates", filename)


@app.route("/")
def index():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("landing.html")


# ── Registration / login / recovery ─────────────────────────────────────────

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        u  = request.form.get("username", "").strip()
        p  = request.form.get("password", "")
        ip = request.remote_addr

        if not u or not p:
            return render_template("register.html", error="Fill both fields")
        if len(p) < 6:
            return render_template("register.html", error="Password must be ≥6 characters")

        db = get_db()
        if db.execute("SELECT 1 FROM users WHERE username=?", (u,)).fetchone():
            return render_template("register.html", error="Username taken")

        is_vpn, vpn_label = ip_intel.is_vpn_or_proxy(ip)
        db.execute(
            "INSERT INTO users(username,password,signup_ip,created_at,is_vpn_signup,vpn_provider)"
            " VALUES(?,?,?,?,?,?)",
            (u, generate_password_hash(p), ip, int(time.time()), int(is_vpn), vpn_label)
        )
        db.commit()
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u   = request.form.get("username", "").strip()
        p   = request.form.get("password", "")
        db  = get_db()
        row = db.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if row and check_password_hash(row["password"], p):
            login_user(User(row), remember=True)
            if not row["recovery_code_shown"]:
                code = generate_recovery_code()
                db.execute(
                    "UPDATE users SET recovery_code_hash=?, recovery_code_shown=1 WHERE id=?",
                    (generate_password_hash(code), row["id"])
                )
                db.commit()
                session["show_recovery_code"] = code
                return redirect(url_for("recovery_code_display"))
            return redirect(url_for("admin" if row["is_admin"] else "dashboard"))
        return render_template("login.html", error="Bad credentials")
    return render_template("login.html")


@app.route("/recovery-code")
@login_required
def recovery_code_display():
    code = session.pop("show_recovery_code", None)
    if not code:
        return redirect(url_for("dashboard"))
    return render_template("recovery_code.html", code=code)


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        u    = request.form.get("username", "").strip()
        code = request.form.get("code", "").strip().upper()
        db   = get_db()
        row  = db.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        if not row or not row["recovery_code_hash"] or \
                not check_password_hash(row["recovery_code_hash"], code):
            return render_template("forgot_password.html", error="Username and recovery code don't match.")
        session["reset_user_id"] = row["id"]
        return redirect(url_for("reset_password"))
    return render_template("forgot_password.html")


@app.route("/reset-password", methods=["GET", "POST"])
def reset_password():
    uid = session.get("reset_user_id")
    if not uid:
        return redirect(url_for("forgot_password"))
    if request.method == "POST":
        pw = request.form.get("password", "")
        if not pw or len(pw) < 6:
            return render_template("reset_password.html", error="Password must be ≥6 characters.")
        db = get_db()
        db.execute("UPDATE users SET password=? WHERE id=?", (generate_password_hash(pw), uid))
        db.commit()
        session.pop("reset_user_id", None)
        return redirect(url_for("login"))
    return render_template("reset_password.html")


@app.route("/logout", methods=["GET","POST"])
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/account/delete", methods=["GET", "POST"])
@login_required
def delete_account():
    if request.method == "POST":
        code = request.form.get("code", "").strip().upper()
        db   = get_db()
        row  = db.execute("SELECT * FROM users WHERE id=?", (current_user.id,)).fetchone()
        if not row or not row["recovery_code_hash"] or \
                not check_password_hash(row["recovery_code_hash"], code):
            return render_template("delete_account.html", error="Incorrect recovery code.")

        for v in db.execute("SELECT * FROM vps WHERE user_id=?", (current_user.id,)).fetchall():
            try:
                destroy_vps(v["container_id"])
            except Exception as e:
                print(f"[DELETE ACCOUNT] Container teardown failed: {e}")

        db.execute("DELETE FROM vps WHERE user_id=?",      (current_user.id,))
        db.execute("DELETE FROM feedback WHERE user_id=?",  (current_user.id,))
        db.execute("DELETE FROM users WHERE id=?",          (current_user.id,))
        db.commit()
        logout_user()
        flash("Your account has been permanently deleted.")
        return redirect(url_for("login"))
    return render_template("delete_account.html")


# ── Dashboard ────────────────────────────────────────────────────────────────

@app.route("/dashboard")
@login_required
def dashboard():
    db      = get_db()
    all_vps = db.execute(
        "SELECT * FROM vps WHERE user_id=? ORDER BY created_at ASC",
        (current_user.id,)
    ).fetchall()

    selected_id = request.args.get("vps_id", type=int)
    vps = None
    if selected_id:
        vps = next((v for v in all_vps if v["id"] == selected_id), None)
    if not vps and all_vps:
        vps = all_vps[0]

    if vps and vps["status"] in ("running", "stopped"):
        real = sync_status(vps["container_id"], vps["status"])
        if real != vps["status"]:
            db.execute("UPDATE vps SET status=? WHERE id=?", (real, vps["id"]))
            db.commit()
            vps = db.execute("SELECT * FROM vps WHERE id=?", (vps["id"],)).fetchone()

    feedback_rows = db.execute(
        "SELECT feedback.*, users.username FROM feedback "
        "JOIN users ON users.id=feedback.user_id "
        "ORDER BY feedback.created_at DESC LIMIT 20"
    ).fetchall()

    queue_pos   = queue.get_position(vps["id"]) if vps and vps["status"] in ("queued", "creating") else 0
    can_feedback = bool(vps and vps["status"] == "running" and vps["ssh_command"])

    # Per-VPS resource limits for display
    limits = {
        "cpu":  get_free_vps_cpu(),
        "ram":  get_free_vps_ram() // 1024,
        "disk": get_free_vps_disk(),
    }

    return render_template(
        "dashboard.html",
        vps=vps, all_vps=all_vps,
        feedback_rows=feedback_rows,
        queue_pos=queue_pos, slot_seconds=queue.SLOT_SECONDS,
        can_feedback=can_feedback,
        limits=limits,
    )


# ── VPS creation — with node overflow routing ────────────────────────────────

@app.route("/vps/create", methods=["POST"])
@login_required
def vps_create():
    db = get_db()
    ip = request.remote_addr

    # One VPS per user (free tier)
    if db.execute("SELECT 1 FROM vps WHERE user_id=?", (current_user.id,)).fetchone():
        return "You already have a VPS", 403
    if db.execute("SELECT 1 FROM vps WHERE creator_ip=?", (ip,)).fetchone():
        return "This IP already owns a VPS", 403
    user_row = db.execute("SELECT signup_ip FROM users WHERE id=?", (current_user.id,)).fetchone()
    if db.execute("SELECT 1 FROM vps WHERE creator_ip=?", (user_row["signup_ip"],)).fetchone():
        return "Your signup IP already owns a VPS", 403

    is_vpn, vpn_label = ip_intel.is_vpn_or_proxy(ip)
    if is_vpn:
        return f"VPN/proxy detected ({vpn_label}) — disable it and try again.", 403

    found_elsewhere, other_url = node_mesh.check_ip_across_mesh(db, ip)
    if found_elsewhere:
        return f"This IP already owns a VPS on another node ({other_url})", 403

    # ── Node overflow: if this node is full, create on peer via API ─────────
    allowed, current_count = can_create_vps()
    if not allowed:
        peer_url, peer_secret = node_mesh.get_peer_for_overflow(db)
        if peer_url and peer_secret:
            now = int(time.time())
            cur = db.execute(
                "INSERT INTO vps(user_id,container_id,creator_ip,created_at,status,node_id)"
                " VALUES(?,?,?,?,'creating',1)",
                (current_user.id, "pending-overflow", ip, now)
            )
            db.commit()
            vps_id = cur.lastrowid
            threading.Thread(
                target=_overflow_build_worker,
                args=(vps_id, current_user.id, ip, peer_url, peer_secret),
                daemon=True,
            ).start()
            flash(f"This node is full — VPS being created on {peer_url}.")
            return redirect(url_for("vps_view", vps_id=vps_id))
        return (
            "This node is full and no other nodes have capacity right now. "
            "Please try again later.", 503
        )

    disk_ok, disk_alloc, disk_budget, disk_msg = can_allocate_disk(get_free_vps_disk())
    if not disk_ok:
        return disk_msg or f"Disk budget reached ({disk_alloc}/{disk_budget} GB).", 503

    now        = int(time.time())
    last_click = _last_create_click.get(ip, 0)
    if now - last_click < CREATE_DEBOUNCE_SECONDS:
        return "Please wait a few seconds before trying again.", 429
    _last_create_click[ip] = now

    cur    = db.execute(
        "INSERT INTO vps(user_id,container_id,creator_ip,created_at,status) VALUES(?,?,?,?,?)",
        (current_user.id, "pending", ip, now, "queued")
    )
    db.commit()
    vps_id = cur.lastrowid

    queue.enqueue(current_user.id, vps_id)
    return redirect(url_for("vps_view", vps_id=vps_id))


def _overflow_build_worker(vps_id: int, user_id: int, ip: str,
                            peer_url: str, peer_secret: str):
    """
    Calls the peer node API to build a VPS there, then stores the result
    (ssh_url from the peer) in our local DB row so the user can see it.
    """
    from vps import get_free_vps_cpu, get_free_vps_ram, get_free_vps_disk
    result = node_mesh.create_vps_on_peer(
        peer_url=peer_url,
        shared_secret=peer_secret,
        my_url=node_mesh.get_node_url(),
        username=f"vps-{user_id}",
        cpu=get_free_vps_cpu(),
        ram_mb=get_free_vps_ram(),
        disk_gb=get_free_vps_disk(),
    )
    db = get_db()
    if "error" in result:
        db.execute(
            "UPDATE vps SET status='failed', ssh_command=?, container_id='overflow-failed' WHERE id=?",
            (result["error"], vps_id)
        )
    else:
        db.execute(
            "UPDATE vps SET status='running', container_id=?, ssh_command=? WHERE id=?",
            (result.get("container_id", "overflow"), result.get("ssh_url", ""), vps_id)
        )
    db.commit()
    db.close()


# ── VPS build workers ────────────────────────────────────────────────────────

def _build_vps(vps_id: int, user_id: int):
    db = get_db()
    db.execute("UPDATE vps SET status='creating' WHERE id=?", (vps_id,))
    db.commit()
    db.close()
    try:
        cid, ssh = create_vps_container(f"vps-{user_id}")
        db = get_db()
        db.execute(
            "UPDATE vps SET container_id=?, ssh_command=?, status='running' WHERE id=?",
            (cid, ssh, vps_id)
        )
        db.commit()
        db.close()
    except Exception as e:
        db = get_db()
        db.execute("UPDATE vps SET status='failed', ssh_command=? WHERE id=?", (str(e), vps_id))
        db.commit()
        db.close()


def _build_vps_custom(vps_id: int, user_id: int, cpu: int, ram_mb: int, disk_gb: int,
                      kvm: bool = False):
    db = get_db()
    db.execute("UPDATE vps SET status='creating' WHERE id=?", (vps_id,))
    db.commit()
    db.close()
    try:
        cid, ssh = create_vps_container(
            f"vps-{user_id}",
            cpu_limit=cpu,
            ram_limit_mb=ram_mb,
            disk_limit_gb=disk_gb,
            kvm_enabled=kvm,
        )
        db = get_db()
        db.execute(
            "UPDATE vps SET container_id=?, ssh_command=?, status='running', kvm_enabled=?"
            " WHERE id=?",
            (cid, ssh, int(kvm), vps_id)
        )
        db.commit()
        db.close()
    except Exception as e:
        db = get_db()
        db.execute("UPDATE vps SET status='failed', ssh_command=? WHERE id=?", (str(e), vps_id))
        db.commit()
        db.close()


# ── VPS view / status polling ────────────────────────────────────────────────

@app.route("/vps/<int:vps_id>")
@login_required
def vps_view(vps_id):
    db  = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps or (vps["user_id"] != current_user.id and not current_user.is_admin):
        return "Not found", 404
    if vps["status"] in ("running", "stopped"):
        real = sync_status(vps["container_id"], vps["status"])
        if real != vps["status"]:
            db.execute("UPDATE vps SET status=? WHERE id=?", (real, vps_id))
            db.commit()
            vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    queue_pos = queue.get_position(vps_id) if vps["status"] in ("queued", "creating") else 0
    return render_template("vps_view.html", vps=vps, queue_pos=queue_pos, slot_seconds=queue.SLOT_SECONDS)


@app.route("/vps/<int:vps_id>/queue_status")
@login_required
def vps_queue_status(vps_id):
    db  = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps or (vps["user_id"] != current_user.id and not current_user.is_admin):
        return jsonify({"error": "no"}), 404
    return jsonify({
        "status":      vps["status"],
        "position":    queue.get_position(vps_id),
        "eta_seconds": queue.get_position(vps_id) * queue.SLOT_SECONDS,
        "ssh_command": vps["ssh_command"],
    })


@app.route("/vps/<int:vps_id>/dismiss", methods=["POST"])
@login_required
def vps_dismiss(vps_id):
    db  = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps or vps["user_id"] != current_user.id:
        return "Not found", 404
    if vps["status"] != "failed":
        return "Only a failed build can be dismissed", 400
    db.execute("DELETE FROM vps WHERE id=?", (vps_id,))
    db.commit()
    return redirect(url_for("dashboard"))


@app.route("/vps/<int:vps_id>/logs")
@login_required
def vps_logs(vps_id):
    db  = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps or (vps["user_id"] != current_user.id and not current_user.is_admin):
        return "Not found", 404

    @stream_with_context
    def gen():
        cid, waited = vps["container_id"], 0
        while cid == "pending" and waited < 600:
            time.sleep(2); waited += 2
            row = get_db().execute(
                "SELECT container_id, status FROM vps WHERE id=?", (vps_id,)
            ).fetchone()
            if not row:
                yield "data: VPS record gone.\n\n"; yield "data: [DONE]\n\n"; return
            cid = row["container_id"]
            if row["status"] == "failed":
                yield f"data: Build failed: {cid}\n\n"; yield "data: [DONE]\n\n"; return
        if cid == "pending":
            yield "data: Build taking too long.\n\n"; yield "data: [DONE]\n\n"; return
        for line in build_logs_stream(cid):
            yield f"data: {line}\n\n"
        yield "data: [DONE]\n\n"

    return Response(gen(), mimetype="text/event-stream")


@app.route("/vps/<int:vps_id>/stats")
@login_required
def vps_stats(vps_id):
    db  = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps or (vps["user_id"] != current_user.id and not current_user.is_admin):
        return jsonify({"error": "no"}), 404
    if vps["status"] != "running":
        return jsonify({"error": "not running", "status": vps["status"]})
    try:
        return jsonify(get_container_stats(vps["container_id"], vps["created_at"]))
    except Exception as e:
        return jsonify({"error": str(e)})


@app.route("/vps/<int:vps_id>/regen_ssh", methods=["POST"])
@login_required
def regen_ssh(vps_id):
    db  = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps:
        flash("VPS not found"); return redirect(url_for("dashboard"))
    if vps["user_id"] != current_user.id and not current_user.is_admin:
        flash("Not your VPS");  return redirect(url_for("dashboard"))
    if vps["status"] != "running":
        flash("VPS must be running"); return redirect(url_for("vps_view", vps_id=vps_id))
    if time.time() - vps["last_regen"] < 30:
        flash("Wait 30s between regens"); return redirect(url_for("vps_view", vps_id=vps_id))
    try:
        new_url = regen_sshx(vps["container_id"])
        if not new_url:
            flash("Could not start a new terminal session")
            return redirect(url_for("vps_view", vps_id=vps_id))
        db.execute("UPDATE vps SET ssh_command=?, last_regen=? WHERE id=?",
                   (new_url, int(time.time()), vps_id))
        db.commit()
        flash("New terminal link generated")
    except Exception as e:
        flash(f"Failed to regenerate: {e}")
    return redirect(url_for("vps_view", vps_id=vps_id))


@app.route("/vps/<int:vps_id>/power/<action>", methods=["POST"])
@login_required
def vps_power(vps_id, action):
    if action not in ("start", "stop", "reinstall"):
        return "Unknown action", 400

    db  = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps:
        flash("VPS not found"); return redirect(url_for("dashboard"))
    if vps["user_id"] != current_user.id and not current_user.is_admin:
        flash("Not your VPS"); return redirect(url_for("dashboard"))

    if vps["status"] in ("running", "stopped"):
        real = sync_status(vps["container_id"], vps["status"])
        if real != vps["status"]:
            db.execute("UPDATE vps SET status=? WHERE id=?", (real, vps_id))
            db.commit()
            vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()

    debounce = REINSTALL_DEBOUNCE_SECONDS if action == "reinstall" else POWER_DEBOUNCE_SECONDS
    now      = time.time()
    if now - _last_power_action.get(vps_id, 0) < debounce:
        flash("Please wait before trying that again.")
        return redirect(url_for("dashboard", vps_id=vps_id))
    _last_power_action[vps_id] = now

    if action == "start":
        if vps["status"] != "stopped":
            flash("VPS must be stopped to start it")
            return redirect(url_for("dashboard", vps_id=vps_id))
        try:
            result = start_vps(vps["container_id"])
            if "error" in result:
                flash(f"Failed: {result['error']}")
            else:
                db.execute("UPDATE vps SET status='running' WHERE id=?", (vps_id,))
                db.commit(); flash("VPS started")
        except Exception as e:
            flash(f"Failed: {e}")

    elif action == "stop":
        if vps["status"] != "running":
            flash("VPS must be running to stop it")
            return redirect(url_for("dashboard", vps_id=vps_id))
        try:
            result = stop_vps(vps["container_id"])
            if "error" in result:
                flash(f"Failed: {result['error']}")
            else:
                db.execute("UPDATE vps SET status='stopped' WHERE id=?", (vps_id,))
                db.commit(); flash("VPS stopped")
        except Exception as e:
            flash(f"Failed: {e}")

    elif action == "reinstall":
        if vps["status"] not in ("running", "stopped", "failed"):
            flash("VPS can't be reinstalled while building")
            return redirect(url_for("dashboard", vps_id=vps_id))
        db.execute("UPDATE vps SET status='creating', ssh_command=NULL WHERE id=?", (vps_id,))
        db.commit()
        had_kvm = bool(vps["kvm_enabled"]) if "kvm_enabled" in vps.keys() else False
        threading.Thread(
            target=_reinstall_worker,
            args=(vps_id, vps["container_id"], f"vps-{vps['user_id']}"),
            kwargs={"kvm": had_kvm},
            daemon=True,
        ).start()
        flash("Reinstalling your VPS — takes a minute or two.")

    return redirect(url_for("dashboard", vps_id=vps_id))


def _reinstall_worker(vps_id: int, old_cid: str, username: str, kvm: bool = False):
    try:
        new_cid, new_ssh = reinstall_vps(old_cid, username, kvm_enabled=kvm)
        db = get_db()
        db.execute(
            "UPDATE vps SET container_id=?, ssh_command=?, status='running', kvm_enabled=?"
            " WHERE id=?",
            (new_cid, new_ssh, int(kvm), vps_id)
        )
        db.commit(); db.close()
    except Exception as e:
        db = get_db()
        db.execute("UPDATE vps SET status='failed', ssh_command=? WHERE id=?", (str(e), vps_id))
        db.commit(); db.close()


# ── In-browser terminal (exec endpoint) ─────────────────────────────────────

@app.route("/vps/<int:vps_id>/terminal/exec", methods=["POST"])
@login_required
def terminal_exec(vps_id):
    """
    One-shot command execution for the in-page terminal.
    POST JSON: {"cmd": "ls -la /root"}
    Returns JSON: {"output": "...", "exit_code": 0}
    """
    db  = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps or (vps["user_id"] != current_user.id and not current_user.is_admin):
        return jsonify({"error": "not found"}), 404
    if vps["status"] != "running":
        return jsonify({"error": "VPS is not running"}), 400

    data = request.get_json(silent=True) or {}
    cmd  = data.get("cmd", "").strip()
    if not cmd:
        return jsonify({"error": "no command"}), 400

    # Very simple guard — block the most obviously dangerous single-shot cmds
    blocked = ["rm -rf /", "mkfs", "> /dev/sda", "dd if="]
    if any(b in cmd for b in blocked):
        return jsonify({"output": "Command blocked.", "exit_code": 1})

    try:
        result = exec_command(vps["container_id"], cmd)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── File manager API ─────────────────────────────────────────────────────────

def _get_owned_vps(vps_id: int):
    db  = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps or (vps["user_id"] != current_user.id and not current_user.is_admin):
        return None
    return vps


@app.route("/vps/<int:vps_id>/files")
@login_required
def file_manager(vps_id):
    vps = _get_owned_vps(vps_id)
    if not vps:
        abort(404)
    if vps["status"] != "running":
        flash("VPS must be running to use the file manager")
        return redirect(url_for("dashboard"))
    path = request.args.get("path", "/root")
    try:
        entries = list_files(vps["container_id"], path)
    except Exception as e:
        entries = []
        flash(str(e))
    return render_template("file_manager.html", vps=vps, path=path, entries=entries)


@app.route("/vps/<int:vps_id>/files/download")
@login_required
def file_download(vps_id):
    vps = _get_owned_vps(vps_id)
    if not vps:
        abort(404)
    path = request.args.get("path", "")
    if not path:
        return "No path specified", 400
    try:
        b64 = read_file_b64(vps["container_id"], path)
        raw = base64.b64decode(b64)
        filename = path.split("/")[-1] or "file"
        return Response(
            raw,
            mimetype="application/octet-stream",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        return str(e), 500


@app.route("/vps/<int:vps_id>/files/upload", methods=["POST"])
@login_required
def file_upload(vps_id):
    vps = _get_owned_vps(vps_id)
    if not vps:
        abort(404)
    if vps["status"] != "running":
        return "VPS not running", 400

    dest_path = request.form.get("path", "/root")
    file      = request.files.get("file")
    if not file or not file.filename:
        flash("No file selected")
        return redirect(url_for("file_manager", vps_id=vps_id, path=dest_path))

    filename  = file.filename.replace(" ", "_")
    b64_data  = base64.b64encode(file.read()).decode()
    full_path = dest_path.rstrip("/") + "/" + filename

    try:
        write_file_b64(vps["container_id"], full_path, b64_data)
        flash(f"Uploaded {filename}")
    except Exception as e:
        flash(f"Upload failed: {e}")

    return redirect(url_for("file_manager", vps_id=vps_id, path=dest_path))


@app.route("/vps/<int:vps_id>/files/delete", methods=["POST"])
@login_required
def file_delete(vps_id):
    vps = _get_owned_vps(vps_id)
    if not vps:
        abort(404)
    path      = request.form.get("path", "")
    back_path = request.form.get("back", "/root")
    if not path:
        return "No path specified", 400
    try:
        delete_file(vps["container_id"], path)
        flash(f"Deleted {path}")
    except Exception as e:
        flash(f"Delete failed: {e}")
    return redirect(url_for("file_manager", vps_id=vps_id, path=back_path))


@app.route("/vps/<int:vps_id>/files/mkdir", methods=["POST"])
@login_required
def file_mkdir(vps_id):
    vps = _get_owned_vps(vps_id)
    if not vps:
        abort(404)
    base = request.form.get("base", "/root")
    name = request.form.get("name", "").strip()
    if not name:
        flash("Folder name required")
        return redirect(url_for("file_manager", vps_id=vps_id, path=base))
    full = base.rstrip("/") + "/" + name
    try:
        create_directory(vps["container_id"], full)
        flash(f"Created {full}")
    except Exception as e:
        flash(f"Failed: {e}")
    return redirect(url_for("file_manager", vps_id=vps_id, path=base))


# ── Feedback ──────────────────────────────────────────────────────────────────

@app.route("/feedback", methods=["POST"])
@login_required
def submit_feedback():
    db  = get_db()
    vps = db.execute(
        "SELECT * FROM vps WHERE user_id=? AND status='running' AND ssh_command IS NOT NULL LIMIT 1",
        (current_user.id,)
    ).fetchone()
    if not vps:
        return "Need a running VPS with terminal access to leave feedback", 403
    try:
        stars = int(request.form.get("stars", 0))
    except ValueError:
        stars = 0
    if not (1 <= stars <= 5):
        return "Stars must be 1–5", 400
    comment = request.form.get("comment", "").strip()[:500]
    db.execute("INSERT INTO feedback(user_id,stars,comment,created_at) VALUES(?,?,?,?)",
               (current_user.id, stars, comment, int(time.time())))
    db.commit()
    return redirect(url_for("dashboard"))


# ── Admin ─────────────────────────────────────────────────────────────────────

@app.route("/admin")
@login_required
def admin():
    if not current_user.is_admin:
        return "Forbidden", 403
    db   = get_db()
    rows = db.execute(
        "SELECT vps.*, users.username FROM vps JOIN users ON users.id=vps.user_id"
    ).fetchall()
    users = db.execute(
        "SELECT id,username,signup_ip,is_admin,created_at,recovery_code_shown,"
        "is_vpn_signup,vpn_provider FROM users"
    ).fetchall()
    queue_entries = queue.peek_all()
    host          = get_host_capacity()
    broadcast     = db.execute("SELECT message, active FROM broadcast WHERE id=1").fetchone()
    config_row    = {
        r["key"]: r["value"]
        for r in db.execute("SELECT key,value FROM panel_config").fetchall()
    }
    return render_template(
        "admin.html",
        vpses=rows, users=users,
        queue_length=queue.queue_length(), queue_entries=queue_entries,
        host=host, broadcast=broadcast, config=config_row,
        max_vps=MAX_VPS_PER_NODE,
        node_code=node_mesh.NODE_CODE,
        node_url=node_mesh.get_node_url(),
        host_kvm=kvm_available(),   # admin.html gates the KVM grant checkbox on this
    )


@app.route("/admin/config", methods=["POST"])
@login_required
def admin_update_config():
    if not current_user.is_admin:
        return "Forbidden", 403
    db = get_db()
    for key in ("vps_cpu_cores", "vps_ram_gb", "vps_disk_gb"):
        val = request.form.get(key, "").strip()
        if val.isdigit() and int(val) > 0:
            db.execute(
                "INSERT INTO panel_config(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, val)
            )
    db.commit()
    flash("Resource limits updated")
    return redirect(url_for("admin"))


@app.route("/admin/broadcast", methods=["POST"])
@login_required
def admin_broadcast_set():
    if not current_user.is_admin:
        return "Forbidden", 403
    message = request.form.get("message", "").strip()[:500]
    if not message:
        flash("Message can't be empty"); return redirect(url_for("admin"))
    db = get_db()
    db.execute("UPDATE broadcast SET message=?, active=1, updated_at=? WHERE id=1",
               (message, int(time.time())))
    db.commit()
    flash("Message posted")
    return redirect(url_for("admin"))


@app.route("/admin/broadcast/clear", methods=["POST"])
@login_required
def admin_broadcast_clear():
    if not current_user.is_admin:
        return "Forbidden", 403
    get_db().execute("UPDATE broadcast SET active=0 WHERE id=1")
    get_db().commit()
    flash("Message cleared")
    return redirect(url_for("admin"))


@app.route("/admin/grant-vps", methods=["POST"])
@login_required
def admin_grant_vps():
    if not current_user.is_admin:
        return "Forbidden", 403
    db       = get_db()
    username = request.form.get("username", "").strip()
    try:
        ram_gb     = int(request.form.get("ram_gb", 0))
        cpu_cores  = int(request.form.get("cpu_cores", 0))
        disk_gb    = int(request.form.get("disk_gb", 0))
    except ValueError:
        return "RAM/CPU/Disk must be numbers", 400

    # KVM: only accepted when the host actually has /dev/kvm
    want_kvm   = bool(request.form.get("kvm_enabled")) and kvm_available()

    if not username:                                return "Username required", 400
    if not (1 <= ram_gb    <= ADMIN_MAX_RAM_GB):    return f"RAM must be 1–{ADMIN_MAX_RAM_GB} GB", 400
    if not (1 <= cpu_cores <= ADMIN_MAX_CPU_CORES): return f"CPU must be 1–{ADMIN_MAX_CPU_CORES}", 400
    if not (1 <= disk_gb   <= ADMIN_MAX_DISK_GB):   return f"Disk must be 1–{ADMIN_MAX_DISK_GB} GB", 400

    host = get_host_capacity()
    if cpu_cores > host["cpu_cores"]:
        return f"Host only has {host['cpu_cores']} cores.", 400
    if ram_gb * 1024 > host["ram_mb"]:
        return f"Host only has {host['ram_mb']//1024}GB RAM.", 400

    disk_ok, disk_alloc, disk_budget, disk_msg = can_allocate_disk(disk_gb)
    if not disk_ok:
        return disk_msg or f"Disk budget reached ({disk_alloc}/{disk_budget} GB).", 400

    target = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if not target:
        return "No user with that username", 404

    allowed, _ = can_create_vps()
    if not allowed:
        return "Node full", 503

    cur    = db.execute(
        "INSERT INTO vps(user_id,container_id,creator_ip,created_at,status,kvm_enabled)"
        " VALUES(?,?,?,?,?,?)",
        (target["id"], "pending", "admin-grant", int(time.time()), "creating", int(want_kvm))
    )
    db.commit()
    vps_id = cur.lastrowid

    threading.Thread(
        target=_build_vps_custom,
        args=(vps_id, target["id"], cpu_cores, ram_gb * 1024, disk_gb, want_kvm),
        daemon=True,
    ).start()

    flash(f"VPS creation started for {username}" + (" (KVM enabled)" if want_kvm else ""))
    return redirect(url_for("admin"))


@app.route("/admin/vps/<int:vps_id>/<action>", methods=["POST"])
@login_required
def admin_vps_action(vps_id, action):
    if not current_user.is_admin:
        return "Forbidden", 403
    db  = get_db()
    vps = db.execute("SELECT * FROM vps WHERE id=?", (vps_id,)).fetchone()
    if not vps:
        return "Not found", 404

    if action == "suspend":
        suspend_vps(vps["container_id"])
        db.execute("UPDATE vps SET status='suspended' WHERE id=?", (vps_id,))

    elif action == "unsuspend":
        unsuspend_vps(vps["container_id"])
        db.execute("UPDATE vps SET status='running' WHERE id=?", (vps_id,))

    elif action == "delete":
        destroy_vps(vps["container_id"])
        db.execute("DELETE FROM vps WHERE id=?", (vps_id,))

    elif action in ("enable_kvm", "disable_kvm"):
        # KVM toggle — only meaningful when the host supports it
        if not kvm_available():
            flash("KVM is not available on this host (/dev/kvm missing).")
            return redirect(url_for("admin"))
        enable = action == "enable_kvm"
        ok     = set_kvm_enabled(vps["container_id"], enable)
        if ok:
            db.execute("UPDATE vps SET kvm_enabled=? WHERE id=?", (int(enable), vps_id))
            flash(f"KVM {'enabled' if enable else 'disabled'} for VPS {vps['container_id'][:12]}.")
        else:
            flash("KVM toggle failed — check server logs.")
        db.commit()
        return redirect(url_for("admin"))

    db.commit()
    return redirect(url_for("admin"))


# ── Admin — nodes tab ─────────────────────────────────────────────────────────

@app.route("/admin/nodes", methods=["GET", "POST"])
@login_required
def admin_nodes():
    if not current_user.is_admin:
        return "Forbidden", 403
    db     = get_db()
    result = None
    if request.method == "POST":
        remote_url  = request.form.get("remote_url",  "").strip()
        remote_code = request.form.get("remote_code", "").strip()
        if not remote_url or not remote_code:
            result = (False, "Enter both the remote node URL and its code.")
        else:
            result = node_mesh.pair_with_node(db, remote_url, remote_code)
    nodes = node_mesh.list_nodes(db)
    now   = int(time.time())
    return render_template(
        "admin_nodes.html",
        nodes=nodes, result=result,
        my_code=node_mesh.NODE_CODE,
        my_url=node_mesh.get_node_url(),
        max_vps=MAX_VPS_PER_NODE,
        now=now,
    )


@app.route("/admin/nodes/<int:node_id>/remove", methods=["POST"])
@login_required
def admin_node_remove(node_id):
    if not current_user.is_admin:
        return "Forbidden", 403
    db = get_db()
    db.execute("DELETE FROM nodes WHERE id=?", (node_id,))
    db.commit()
    flash("Node removed")
    return redirect(url_for("admin_nodes"))


# ── Mesh API — called by other nodes ─────────────────────────────────────────

@app.route("/api/node/pair", methods=["POST"])
def api_node_pair():
    """
    Another node POSTs here with Authorization: <this_node's_code>
    and JSON body {"my_url": "<their url>"}.
    """
    code          = request.headers.get("Authorization", "")
    data          = request.get_json(silent=True) or {}
    requester_url = data.get("my_url", "")
    db            = get_db()
    ok, result    = node_mesh.accept_pairing(db, code, requester_url)
    if not ok:
        return jsonify({"error": result}), 403
    return jsonify({"shared_secret": result})


@app.route("/api/node/check_ip", methods=["POST"])
def api_node_check_ip():
    """
    Paired node POSTs here with Authorization: <shared_secret>
    and JSON body {"ip": "..."}.
    """
    db         = get_db()
    peer_url   = request.headers.get("X-Node-Url", "")
    secret     = request.headers.get("Authorization", "")
    if not node_mesh.verify_peer_secret(db, peer_url, secret):
        return jsonify({"error": "unauthorized"}), 403

    data = request.get_json(silent=True) or {}
    ip   = data.get("ip", "")
    if not ip:
        return jsonify({"error": "missing ip"}), 400

    has_vps = bool(db.execute("SELECT 1 FROM vps WHERE creator_ip=?", (ip,)).fetchone())
    if not has_vps:
        has_vps = bool(db.execute(
            "SELECT 1 FROM vps JOIN users ON users.id=vps.user_id WHERE users.signup_ip=?", (ip,)
        ).fetchone())
    return jsonify({"has_vps": has_vps})


@app.route("/api/node/stats", methods=["POST"])
def api_node_stats():
    """
    Paired node POSTs its current stats here every 60s so our nodes table
    stays fresh for the admin nodes view.
    """
    db       = get_db()
    peer_url = request.headers.get("X-Node-Url", "")
    secret   = request.headers.get("Authorization", "")
    if not node_mesh.verify_peer_secret(db, peer_url, secret):
        return jsonify({"error": "unauthorized"}), 403

    data = request.get_json(silent=True) or {}
    node_mesh.update_peer_stats(
        db,
        peer_url=peer_url,
        vps_count=data.get("vps_count", 0),
        cpu_cores=data.get("cpu_cores", 0),
        ram_mb=data.get("ram_mb", 0),
        disk_gb=data.get("disk_gb", 0),
    )
    return jsonify({"ok": True})

@app.route("/api/node/create_vps", methods=["POST"])
def api_node_create_vps():
    """
    Overflow VPS creation endpoint.
    Another node POSTs here when it is full and wants us to build a VPS.
    Authorization: <shared_secret>  X-Node-Url: <their url>
    Body: {username, cpu, ram_mb, disk_gb, origin_url}
    Returns: {container_id, ssh_url} or {error}
    """
    db       = get_db()
    peer_url = request.headers.get("X-Node-Url", "")
    secret   = request.headers.get("Authorization", "")
    if not node_mesh.verify_peer_secret(db, peer_url, secret):
        return jsonify({"error": "unauthorized"}), 403

    data = request.get_json(silent=True) or {}
    username = data.get("username", "overflow-user")
    cpu      = int(data.get("cpu",     get_free_vps_cpu()))
    ram_mb   = int(data.get("ram_mb",  get_free_vps_ram()))
    disk_gb  = int(data.get("disk_gb", get_free_vps_disk()))

    allowed, _ = can_create_vps()
    if not allowed:
        return jsonify({"error": "This node is also full"}), 503

    try:
        cid, ssh_url = create_vps_container(
            username, cpu_limit=cpu, ram_limit_mb=ram_mb, disk_limit_gb=disk_gb
        )
        return jsonify({"container_id": cid, "ssh_url": ssh_url})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/node/bootstrap_status")
@login_required
def api_bootstrap_status():
    """Returns bootstrap log lines for a peer node (admin only, for the nodes tab)."""
    if not current_user.is_admin:
        return jsonify({"error": "forbidden"}), 403
    peer_url = request.args.get("url", "").strip()
    if not peer_url:
        return jsonify({"error": "missing url"}), 400
    logs = node_mesh.get_bootstrap_logs(peer_url)
    return jsonify({"logs": logs, "done": any("complete" in l.lower() or "error" in l.lower() for l in logs[-3:])})


# ── Notifications ─────────────────────────────────────────────────────────────

@app.route("/api/notifications/latest")
@login_required
def api_notifications_latest():
    since = request.args.get("since", type=int, default=0)
    db    = get_db()
    rows  = db.execute(
        "SELECT id,message,created_at FROM notifications WHERE created_at>? "
        "ORDER BY created_at ASC LIMIT 20",
        (since,)
    ).fetchall()
    return jsonify({"notifications": [dict(r) for r in rows], "now": int(time.time())})


# ── Startup ───────────────────────────────────────────────────────────────────


@app.route("/vps/stats_summary")
@login_required
def vps_stats_summary():
    """Quick count of VPSes on this node for the nodes admin tab."""
    if not current_user.is_admin:
        return jsonify({"error":"forbidden"}), 403
    db  = get_db()
    cnt = db.execute("SELECT COUNT(*) FROM vps WHERE status NOT IN ('failed','deleted')").fetchone()[0]
    return jsonify({"vps_count": cnt, "max": MAX_VPS_PER_NODE})


@app.template_filter('strftime')
def strftime_filter(ts):
    try:
        return datetime.datetime.fromtimestamp(int(ts)).strftime('%Y-%m-%d %H:%M')
    except Exception:
        return str(ts)
import datetime

if __name__ == "__main__":
    init_db()
    print("=" * 55)
    print(f"  NODE CODE : {node_mesh.NODE_CODE}")
    print("  Share this with another node admin to pair nodes.")
    print("  URL is auto-detected from the first incoming request.")
    print("=" * 55)
    start_monitor()
    queue.start_queue_worker(_build_vps)
    app.run(host="0.0.0.0", port=5000, threaded=True)
