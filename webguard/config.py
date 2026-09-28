import json
from pathlib import Path

DEFAULTS = {
    "max_pages": 10,
    "delay": 0.8,
    "timeout": 12,
    "respect_robots": True,
    "safe_active": False,
    "scope_hosts": [],
}

def load_config(path=None):
    data = dict(DEFAULTS)
    if path:
        parsed = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(parsed, dict):
            raise ValueError("Config harus berupa JSON object.")
        data.update(parsed)
    return data
