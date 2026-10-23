"""
NetRunner OS - Run registry (persistent)

Records what traffic was generated or replayed - scenario, IPs, and time window -
so the ExtraHop detection loop can correlate detections back to a run, and so a
validation report can be reproduced later. Persisted to data/runs.json (JSON,
stdlib only) so history survives an app restart.

`recent_runs` is a plain list, oldest first, capped to the most recent entries.
It is re-exported from app.core.engine for backwards compatibility.
"""

import os
import json
import time
from threading import Lock

RUNS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
    'data', 'runs.json'
)

_MAX = 200
_lock = Lock()

recent_runs = []  # oldest first; detection routes reverse it for display


def _load():
    try:
        with open(RUNS_FILE) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError, IOError, ValueError):
        return
    if isinstance(data, list):
        recent_runs.clear()
        recent_runs.extend(data[-_MAX:])


def _save():
    try:
        os.makedirs(os.path.dirname(RUNS_FILE), exist_ok=True)
        with open(RUNS_FILE, 'w') as f:
            json.dump(recent_runs[-_MAX:], f, indent=2)
    except IOError:
        pass


def register_run(info):
    """Record the start of a run; returns its id. `info` carries scenario/IPs."""
    with _lock:
        rid = f"run-{int(time.time() * 1000)}-{len(recent_runs)}"
        record = {'id': rid, 'start_ms': int(time.time() * 1000), 'end_ms': None}
        record.update(info)
        recent_runs.append(record)
        if len(recent_runs) > _MAX:
            del recent_runs[:-_MAX]
        _save()
        return rid


def finish_run(rid):
    """Stamp a run's end time."""
    with _lock:
        for r in recent_runs:
            if r['id'] == rid and r['end_ms'] is None:
                r['end_ms'] = int(time.time() * 1000)
                _save()
                return


def clear_runs():
    """Drop all recorded runs."""
    with _lock:
        recent_runs.clear()
        _save()


_load()  # restore persisted history at import
