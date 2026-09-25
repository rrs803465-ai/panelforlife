"""
Background monitor thread.

Every 15s: scans all running containers for high CPU + mining signals.
Every 60s: pushes this node's stats to all mesh peers.
"""

import threading
import time
import sqlite3

from vps import handle_high_cpu, get_host_capacity, get_allocated_disk_gb
import node_mesh

DB = "panel.db"
CPU_THRESHOLD = 90.0
STATS_PUSH_INTERVAL = 60


def _get_db():
    import sqlite3
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return db


def watch():
    last_stats_push = 0

    while True:
        try:
            db = _get_db()

            # --- Mining / high-CPU scan ---
            rows = db.execute(
                "SELECT container_id FROM vps WHERE status='running'"
            ).fetchall()

            for row in rows:
                cid = row["container_id"]
                if not cid or cid == "pending":
                    continue
                try:
                    result = handle_high_cpu(cid, threshold=CPU_THRESHOLD)
                    if result["action"] == "suspended":
                        db.execute(
                            "UPDATE vps SET status='suspended' WHERE container_id=?",
                            (cid,)
                        )
                        db.commit()
                        print(
                            f"[MONITOR] SUSPENDED {cid[:12]} — "
                            f"CPU {result['cpu_percent']}% — "
                            f"mining confirmed: {result['reasons']}"
                        )
                    elif result["action"] == "flagged_for_review":
                        print(
                            f"[MONITOR] FLAGGED (not suspended) {cid[:12]} — "
                            f"CPU {result['cpu_percent']}% — "
                            f"weak signals: {result['reasons']}"
                        )
                    elif result["action"] == "none" and result.get("cpu_percent", 0) >= CPU_THRESHOLD:
                        print(
                            f"[MONITOR] {cid[:12]} at {result['cpu_percent']}% CPU — "
                            f"no mining evidence, left running"
                        )
                except Exception as e:
                    print(f"[MONITOR] Error checking {cid[:12]}: {e}")

            # --- Stats push to mesh peers ---
            now = time.time()
            if now - last_stats_push >= STATS_PUSH_INTERVAL:
                try:
                    host = get_host_capacity()
                    vps_count = db.execute(
                        "SELECT COUNT(*) FROM vps WHERE status NOT IN ('failed','deleted')"
                    ).fetchone()[0]
                    node_mesh.push_stats_to_peers(
                        db,
                        vps_count=vps_count,
                        cpu_cores=host["cpu_cores"],
                        ram_mb=host["ram_mb"],
                        disk_gb=host.get("real_disk_gb", 0),
                    )
                    last_stats_push = now
                except Exception as e:
                    print(f"[MONITOR] Stats push error: {e}")

            db.close()

        except Exception as e:
            print(f"[MONITOR] Outer loop error: {e}")

        time.sleep(15)


def start_monitor():
    t = threading.Thread(target=watch, daemon=True)
    t.start()
