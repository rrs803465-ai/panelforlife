"""
Serialized VPS build queue.

One worker thread, one build at a time, SLOT_SECONDS pacing between builds.
Eliminates LXD SQLite contention from concurrent creation requests.

Queue lives in memory — if the process restarts, waiting users need to
re-click Create VPS. Acceptable tradeoff for a single-process panel.
"""

import threading
import time
from collections import deque

SLOT_SECONDS = 15

_lock = threading.Lock()
_queue: deque = deque()  # list of {"user_id":, "vps_id":}


def enqueue(user_id: int, vps_id: int):
    with _lock:
        _queue.append({"user_id": user_id, "vps_id": vps_id})


def get_position(vps_id: int) -> int:
    """1-indexed queue position, or 0 if not queued."""
    with _lock:
        for i, entry in enumerate(_queue):
            if entry["vps_id"] == vps_id:
                return i + 1
    return 0


def queue_length() -> int:
    with _lock:
        return len(_queue)


def peek_all() -> list:
    """Admin panel snapshot — who's waiting, in order."""
    with _lock:
        return list(_queue)


def _worker(build_fn):
    while True:
        entry = None
        with _lock:
            if _queue:
                entry = _queue.popleft()
        if entry:
            print(
                f"[QUEUE] Building vps_id={entry['vps_id']} "
                f"for user_id={entry['user_id']} "
                f"({queue_length()} still waiting)"
            )
            try:
                build_fn(entry["vps_id"], entry["user_id"])
            except Exception as e:
                print(f"[QUEUE] build_fn raised: {e}")
            time.sleep(SLOT_SECONDS)
        else:
            time.sleep(1)


def start_queue_worker(build_fn):
    """
    build_fn(vps_id, user_id) — the function that actually provisions a
    container and updates the DB. Passed in to avoid circular imports.
    """
    t = threading.Thread(target=_worker, args=(build_fn,), daemon=True)
    t.start()
