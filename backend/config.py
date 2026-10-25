"""Operator-owned local configuration. No credentials are shipped in Git."""
from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / ".local" / "access.json"
ROLES = {"admin", "soc", "grc"}


@dataclass(frozen=True)
class Settings:
    state_dir: Path
    role_keys: dict[str, str] = field(repr=False)
    max_body_bytes: int = 32 * 1024 * 1024
    max_sessions: int = 2000
    max_alert_rows: int = 50000

    def __post_init__(self):
        if set(self.role_keys) != ROLES:
            raise ValueError("Configure separate admin, soc and grc keys")
        if any(not isinstance(v, str) or not v.isascii() or len(v) < 32 or len(v) > 256 for v in self.role_keys.values()):
            raise ValueError("Every role key must contain 32..256 ASCII characters")
        if len(set(self.role_keys.values())) != 3:
            raise ValueError("Role keys must be distinct")
        if not 1 <= self.max_body_bytes <= 32 * 1024 * 1024:
            raise ValueError("Invalid request-size limit")
        if not 1 <= self.max_sessions <= 2000 or not 1 <= self.max_alert_rows <= 50000:
            raise ValueError("Invalid batch/session limits")
        object.__setattr__(self, "state_dir", Path(self.state_dir).resolve())

    @classmethod
    def load(cls, path: Path = CONFIG) -> "Settings":
        if not path.is_file():
            raise ValueError("Run python -m backend init first")
        payload = json.loads(path.read_text(encoding="utf-8"))
        state = Path(payload.get("state_dir", ".local/state"))
        return cls(state if state.is_absolute() else ROOT / state, payload["role_keys"])


def initialize(path: Path = CONFIG) -> Path:
    """Create once, refusing to overwrite operator credentials."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {"state_dir": ".local/state", "role_keys": {r: secrets.token_urlsafe(32) for r in sorted(ROLES)}}
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(payload, stream, indent=2)
        stream.write("\n")
    return path
