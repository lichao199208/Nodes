# -*- coding: utf-8 -*-
"""Persistent inventory snapshots and audit log for Nodes-ops (P2)."""

from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

_lock = threading.Lock()

INVENTORY_FILE = "inventory.json"
INVENTORY_HISTORY_FILE = "inventory_history.jsonl"
AUDIT_FILE = "audit.jsonl"
HISTORY_MAX_LINES = 720  # ~30 days if hourly
AUDIT_MAX_LINES = 2000


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _path(data_dir, name):
    root = Path(data_dir) if data_dir else None
    if not root:
        return None
    root.mkdir(parents=True, exist_ok=True)
    return root / name


def _trim_jsonl(path, keep):
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return
    if len(lines) <= keep:
        return
    path.write_text("\n".join(lines[-keep:]) + "\n", encoding="utf-8")


def save_inventory_snapshot(data_dir, inventory, min_interval_sec=300):
    """Write latest inventory.json and append a history point (throttled)."""
    latest = _path(data_dir, INVENTORY_FILE)
    history = _path(data_dir, INVENTORY_HISTORY_FILE)
    if not latest or not history:
        return None
    payload = dict(inventory or {})
    payload["recorded_at"] = _now_iso()
    payload["recorded_unix"] = int(time.time())
    point = {
        "recorded_at": payload["recorded_at"],
        "recorded_unix": payload["recorded_unix"],
        "scanned": int(payload.get("scanned") or 0),
        "accepted": int(payload.get("accepted") or 0),
        "rejected": int(payload.get("rejected") or 0),
        "version": int(payload.get("version") or 0),
        "profile_id": str(payload.get("profile_id") or ""),
    }
    with _lock:
        latest.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        append = True
        if history.exists():
            try:
                lines = history.read_text(encoding="utf-8").splitlines()
                if lines:
                    last = json.loads(lines[-1])
                    age = point["recorded_unix"] - int(last.get("recorded_unix") or 0)
                    same = (
                        int(last.get("accepted") or 0) == point["accepted"]
                        and int(last.get("rejected") or 0) == point["rejected"]
                        and str(last.get("profile_id") or "") == point["profile_id"]
                    )
                    if same and age < int(min_interval_sec):
                        append = False
            except (OSError, ValueError, TypeError):
                append = True
        if append:
            with history.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(point, ensure_ascii=False) + "\n")
            _trim_jsonl(history, HISTORY_MAX_LINES)
    return payload


def load_inventory_latest(data_dir):
    path = _path(data_dir, INVENTORY_FILE)
    if not path or not path.exists():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def load_inventory_history(data_dir, limit=48):
    path = _path(data_dir, INVENTORY_HISTORY_FILE)
    if not path or not path.exists():
        return []
    try:
        limit = max(1, min(500, int(limit)))
    except (TypeError, ValueError):
        limit = 48
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    rows = []
    for line in lines[-limit:]:
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if isinstance(item, dict):
            rows.append(item)
    return rows


def append_audit(data_dir, kind, action, detail=None, actor="web"):
    path = _path(data_dir, AUDIT_FILE)
    if not path:
        return None
    entry = {
        "at": _now_iso(),
        "unix": int(time.time()),
        "kind": str(kind or "system"),
        "action": str(action or ""),
        "actor": str(actor or "web"),
        "detail": detail if isinstance(detail, dict) else {"message": str(detail or "")},
    }
    with _lock:
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(entry, ensure_ascii=False) + "\n")
        _trim_jsonl(path, AUDIT_MAX_LINES)
    return entry


def load_audit(data_dir, kind=None, limit=50):
    path = _path(data_dir, AUDIT_FILE)
    if not path or not path.exists():
        return []
    try:
        limit = max(1, min(500, int(limit)))
    except (TypeError, ValueError):
        limit = 50
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return []
    wanted = str(kind or "").strip().lower()
    rows = []
    for line in reversed(lines):
        try:
            item = json.loads(line)
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        if wanted and str(item.get("kind") or "").lower() != wanted:
            continue
        rows.append(item)
        if len(rows) >= limit:
            break
    return rows
