import json
import time
import uuid
from pathlib import Path
from typing import Any

from .settings import ENTERPRISE_AUDIT_FILE

def load_json(path: Path, default: Any):
    if not path.exists():
        return default
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default

def save_json(path: Path, value: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(value, indent=2, sort_keys=True), encoding="utf-8")
    tmp.replace(path)

def now() -> int:
    return int(time.time())

def audit(event_type: str, **details):
    event = {
        "event_id": str(uuid.uuid4()),
        "timestamp": now(),
        "event_type": event_type,
        **details,
    }
    ENTERPRISE_AUDIT_FILE.parent.mkdir(parents=True, exist_ok=True)
    with ENTERPRISE_AUDIT_FILE.open("a", encoding="utf-8") as f:
        f.write(json.dumps(event, sort_keys=True) + "\n")
    return event
