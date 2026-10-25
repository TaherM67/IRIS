# IRIS EXPLAIN: File purpose: Validates local role keys and bounded processing settings, and creates private credentials once
# IRIS EXPLAIN: without overwriting them.
# IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string so
# IRIS EXPLAIN: its value does not change.
"""Operator-owned local configuration. No credentials are shipped in Git."""
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import json to encode and decode structured finite JSON payloads.
import json
# IRIS EXPLAIN: Import os to create private files exclusively and inspect platform/file flags.
import os
# IRIS EXPLAIN: Import secrets to generate local role keys and compare them without ordinary equality timing.
import secrets
# IRIS EXPLAIN: Import dataclass, field from dataclasses to declare validated structured settings/source containers.
from dataclasses import dataclass, field
# IRIS EXPLAIN: Import Path from pathlib to resolve server-owned paths without trusting uploaded filenames.
from pathlib import Path

# IRIS EXPLAIN: Store Path(__file__).resolve().parents[1] in ROOT; later lines use this named result.
ROOT = Path(__file__).resolve().parents[1]
# IRIS EXPLAIN: Store the computed value ROOT / '.local' / 'access.json' in CONFIG; later lines use this named result.
CONFIG = ROOT / ".local" / "access.json"
# IRIS EXPLAIN: Store {'admin', 'soc', 'grc'} in ROLES; later lines use this named result.
ROLES = {"admin", "soc", "grc"}


# IRIS EXPLAIN: Generate the structured dataclass constructor/fields from the existing annotations and declared options.
@dataclass(frozen=True)
# IRIS EXPLAIN: Class Settings: Validated local role credentials and bounded processing limits; the dataclass validation runs at
# IRIS EXPLAIN: construction.
class Settings:
    # IRIS EXPLAIN: Declare the existing state_dir field and its type; the surrounding dataclass/schema supplies construction
    # IRIS EXPLAIN: behavior.
    state_dir: Path
    # IRIS EXPLAIN: Store the result of field(repr=False) in role_keys; later lines use this named result.
    role_keys: dict[str, str] = field(repr=False)
    # IRIS EXPLAIN: Store the computed value 32 * 1024 * 1024 in max_body_bytes; later lines use this named result.
    max_body_bytes: int = 32 * 1024 * 1024
    # IRIS EXPLAIN: Store 2000 in max_sessions; later lines use this named result.
    max_sessions: int = 2000
    # IRIS EXPLAIN: Store 50000 in max_alert_rows; later lines use this named result.
    max_alert_rows: int = 50000

    # IRIS EXPLAIN: Function Settings.__post_init__: Enforce three distinct ASCII role keys and bounded body/session/alert
    # IRIS EXPLAIN: limits, then normalize the private state directory.
    def __post_init__(self):
        # IRIS EXPLAIN: Enter this branch only when set(self.role_keys) != ROLES.
        if set(self.role_keys) != ROLES:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Configure separate admin, soc and
            # IRIS EXPLAIN: grc keys'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError("Configure separate admin, soc and grc keys")
        # IRIS EXPLAIN: Enter this branch only when any((not isinstance(v, str) or not v.isascii() or len(v) < 32 or (len(v) >
        # IRIS EXPLAIN: 256) for v in self.role_keys.values())).
        if any(not isinstance(v, str) or not v.isascii() or len(v) < 32 or len(v) > 256 for v in self.role_keys.values()):
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Every role key must contain 32..256
            # IRIS EXPLAIN: ASCII characters'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError("Every role key must contain 32..256 ASCII characters")
        # IRIS EXPLAIN: Enter this branch only when len(set(self.role_keys.values())) != 3.
        if len(set(self.role_keys.values())) != 3:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Role keys must be distinct'); the
            # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError("Role keys must be distinct")
        # IRIS EXPLAIN: Enter this branch only when not 1 <= self.max_body_bytes <= 32 * 1024 * 1024.
        if not 1 <= self.max_body_bytes <= 32 * 1024 * 1024:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Invalid request-size limit'); the
            # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError("Invalid request-size limit")
        # IRIS EXPLAIN: Enter this branch only when not 1 <= self.max_sessions <= 2000 or not 1 <= self.max_alert_rows <= 50000.
        if not 1 <= self.max_sessions <= 2000 or not 1 <= self.max_alert_rows <= 50000:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Invalid batch/session limits'); the
            # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError("Invalid batch/session limits")
        # IRIS EXPLAIN: Call object.__setattr__(self, 'state_dir', Path(self.state_dir).resolve()) using the existing explicit
        # IRIS EXPLAIN: arguments.
        object.__setattr__(self, "state_dir", Path(self.state_dir).resolve())

    # IRIS EXPLAIN: Bind the following helper to the class (cls), used here for shared setup/construction behavior.
    @classmethod
    # IRIS EXPLAIN: Function Settings.load: Read existing local credentials/settings, resolve a relative state path under the
    # IRIS EXPLAIN: repository, and reject absent initialization.
    # IRIS EXPLAIN: Inputs: path: the explicit local file path used by this helper.
    # IRIS EXPLAIN: Declared return type: 'Settings'; the return statements below show each actual result/fallback.
    def load(cls, path: Path = CONFIG) -> "Settings":
        # IRIS EXPLAIN: Enter this branch only when not path.is_file().
        if not path.is_file():
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Run python -m backend init first');
            # IRIS EXPLAIN: the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError("Run python -m backend init first")
        # IRIS EXPLAIN: Store the result of json.loads(path.read_text(encoding='utf-8')) (decode the existing JSON text) in
        # IRIS EXPLAIN: payload; later lines use this named result.
        payload = json.loads(path.read_text(encoding="utf-8"))
        # IRIS EXPLAIN: Store the result of Path(payload.get('state_dir', '.local/state')) in state; later lines use this named
        # IRIS EXPLAIN: result.
        state = Path(payload.get("state_dir", ".local/state"))
        # IRIS EXPLAIN: Return the result of cls(state if state.is_absolute() else ROOT / state, payload['role_keys']) to the
        # IRIS EXPLAIN: caller; this ends the current function path.
        return cls(state if state.is_absolute() else ROOT / state, payload["role_keys"])


# IRIS EXPLAIN: Function initialize: Create private local role keys once with exclusive file creation; never overwrite an
# IRIS EXPLAIN: operator's existing access file.
# IRIS EXPLAIN: Inputs: path: the explicit local file path used by this helper.
# IRIS EXPLAIN: Declared return type: Path; the return statements below show each actual result/fallback.
def initialize(path: Path = CONFIG) -> Path:
    # IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string
    # IRIS EXPLAIN: so its value does not change.
    """Create once, refusing to overwrite operator credentials."""
    # IRIS EXPLAIN: Call path.parent.mkdir(parents=True, exist_ok=True): create the required directory if permitted by the
    # IRIS EXPLAIN: existing flags.
    path.parent.mkdir(parents=True, exist_ok=True)
    # IRIS EXPLAIN: Store a mapping containing state_dir, role_keys in payload; later lines use this named result.
    payload = {"state_dir": ".local/state", "role_keys": {r: secrets.token_urlsafe(32) for r in sorted(ROLES)}}
    # IRIS EXPLAIN: Store the result of os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 384) (open the specified file using
    # IRIS EXPLAIN: its existing mode) in descriptor; later lines use this named result.
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    # IRIS EXPLAIN: Enter os.fdopen(descriptor, 'w', encoding='utf-8') as stream; its context manager supplies the existing
    # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        # IRIS EXPLAIN: Call json.dump(payload, stream, indent=2) using the existing explicit arguments.
        json.dump(payload, stream, indent=2)
        # IRIS EXPLAIN: Call stream.write('\n'): write the already prepared payload.
        stream.write("\n")
    # IRIS EXPLAIN: Return path to the caller; this ends the current function path.
    return path
