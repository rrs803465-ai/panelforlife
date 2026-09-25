"""
First-run setup: creates the admin account AND sets the global per-VPS
resource limits that every free-tier VPS will receive. These limits are
written into the panel_config table and read at runtime by app.py — you
never need to edit vps.py to change them.

Run once:  python setup.py
"""

import sqlite3
import getpass
import time
from werkzeug.security import generate_password_hash

DB = "panel.db"


def init():
    con = sqlite3.connect(DB)
    c = con.cursor()

    # --- Schema (mirror of app.py init_db, kept in sync manually) ---
    c.executescript("""
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
        disk_gb INTEGER DEFAULT 0
    );
    CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message TEXT NOT NULL,
        created_at INTEGER NOT NULL
    );
    """)
    con.commit()

    # --- Admin account ---
    c.execute("SELECT COUNT(*) FROM users WHERE is_admin=1")
    if c.fetchone()[0] == 0:
        print("\n╔══════════════════════════════════════╗")
        print("║        Panel4Life — First Run        ║")
        print("╚══════════════════════════════════════╝\n")

        print("[ Admin Account Setup ]")
        username = input("  Admin username: ").strip()
        while not username:
            username = input("  Username cannot be empty: ").strip()

        password = getpass.getpass("  Admin password: ")
        while len(password) < 6:
            password = getpass.getpass("  Password must be ≥6 chars, try again: ")

        c.execute(
            "INSERT INTO users(username,password,signup_ip,is_admin,created_at,"
            "recovery_code_shown) VALUES(?,?,?,1,?,1)",
            (username, generate_password_hash(password), "127.0.0.1", int(time.time()))
        )
        print(f"\n  ✓ Admin '{username}' created.\n")
    else:
        print("\n  Admin account already exists — skipping account creation.\n")

    # --- Per-VPS resource limits ---
    existing = {
        row[0]: row[1]
        for row in c.execute("SELECT key, value FROM panel_config").fetchall()
    }

    config_keys = ["vps_cpu_cores", "vps_ram_gb", "vps_disk_gb"]
    needs_config = any(k not in existing for k in config_keys)

    if needs_config:
        print("[ Per-VPS Resource Limits ]")
        print("  These limits apply to every free-tier VPS created through the panel.")
        print("  Admin-granted VPSes can override these from the admin panel.\n")

        def ask_int(prompt, default, min_val, max_val):
            while True:
                raw = input(f"  {prompt} [{default}]: ").strip()
                if not raw:
                    return default
                try:
                    val = int(raw)
                    if min_val <= val <= max_val:
                        return val
                    print(f"    Must be between {min_val} and {max_val}.")
                except ValueError:
                    print("    Enter a whole number.")

        cpu = ask_int("CPU cores per VPS (1–32)", default=4, min_val=1, max_val=32)
        ram = ask_int("RAM per VPS in GB (1–256)", default=4, min_val=1, max_val=256)
        disk = ask_int("Disk per VPS in GB (5–2000)", default=80, min_val=5, max_val=2000)

        for key, value in [
            ("vps_cpu_cores", str(cpu)),
            ("vps_ram_gb", str(ram)),
            ("vps_disk_gb", str(disk)),
        ]:
            c.execute(
                "INSERT INTO panel_config(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value)
            )

        print(f"\n  ✓ Each VPS will get: {cpu} vCPU / {ram}GB RAM / {disk}GB disk\n")
    else:
        cpu = existing["vps_cpu_cores"]
        ram = existing["vps_ram_gb"]
        disk = existing["vps_disk_gb"]
        print(f"  Resource limits already set: {cpu} vCPU / {ram}GB RAM / {disk}GB disk")
        change = input("  Change them? [y/N]: ").strip().lower()
        if change == "y":
            def ask_int(prompt, default, min_val, max_val):
                while True:
                    raw = input(f"  {prompt} [{default}]: ").strip()
                    if not raw:
                        return default
                    try:
                        val = int(raw)
                        if min_val <= val <= max_val:
                            return val
                        print(f"    Must be between {min_val} and {max_val}.")
                    except ValueError:
                        print("    Enter a whole number.")

            cpu  = ask_int("CPU cores per VPS (1–32)", int(cpu), 1, 32)
            ram  = ask_int("RAM per VPS in GB (1–256)", int(ram), 1, 256)
            disk = ask_int("Disk per VPS in GB (5–2000)", int(disk), 5, 2000)

            for key, value in [
                ("vps_cpu_cores", str(cpu)),
                ("vps_ram_gb", str(ram)),
                ("vps_disk_gb", str(disk)),
            ]:
                c.execute(
                    "INSERT INTO panel_config(key,value) VALUES(?,?) "
                    "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    (key, value)
                )
            print(f"\n  ✓ Updated: {cpu} vCPU / {ram}GB RAM / {disk}GB disk\n")

    # Seed broadcast row
    c.execute("INSERT OR IGNORE INTO broadcast(id,message,active,updated_at) VALUES(1,'',0,0)")
    con.commit()
    con.close()

    print("Setup complete. Start the panel with:  python app.py\n")


if __name__ == "__main__":
    init()
