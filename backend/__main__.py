"""Run from the repository root: python -m backend <command>."""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

from .config import CONFIG, ROOT, Settings, initialize


def main():
    parser = argparse.ArgumentParser(description="IRIS local shadow-backend prototype")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Generate local role keys once; never commit .local")
    commands.add_parser("keys", help="Print your local role keys; do not share or screen-record them")
    commands.add_parser("check", help="Check dependencies and load the pinned user model")
    smoke = commands.add_parser("smoke", help="Run the actual model adapter and SQLite path without HTTP")
    smoke.add_argument("--state", type=Path, default=ROOT / ".local/smoke")
    serve = commands.add_parser("serve", help="Start one local Uvicorn worker on 127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    args = parser.parse_args()
    try:
        if args.command == "init":
            print(f"Created {initialize()}. Run python -m backend keys to view the three role keys privately.")
        elif args.command == "keys":
            settings = Settings.load()
            for role, key in settings.role_keys.items():
                print(f"{role}: {key}")
        elif args.command == "check":
            missing = [name for name in ("fastapi", "uvicorn", "httpx", "python_multipart") if importlib.util.find_spec(name) is None]
            if missing:
                raise ValueError("Missing web dependencies: " + ", ".join(missing) + "; install requirements-backend.txt")
            from .model_adapter import ModelAdapter
            print(json.dumps(ModelAdapter().status(), indent=2))
            print("Dependencies/model load checked. This is not an HTTP test: run the HTTP test suite next.")
        elif args.command == "smoke":
            from .core import Engine
            keys = {r: "local-smoke-only-" + r + "-" * 40 for r in ("admin", "soc", "grc")}
            engine = Engine(Settings(args.state, keys))
            result = engine.sample("admin")
            print(json.dumps({k: result[k] for k in ("run_id", "status", "sessions", "shadow_class_counts", "model_sha256", "reused_existing_run", "training_labels_read", "automatic_execution", "official_risk_register_write")}, indent=2))
        else:
            if sys.version_info[:2] != (3, 12):
                raise ValueError("Use Python 3.12, matching the documented model environment")
            if not 1 <= args.port <= 65535:
                raise ValueError("Invalid port")
            Settings.load()
            import uvicorn
            uvicorn.run("backend.app:create_app", factory=True, host="127.0.0.1", port=args.port,
                        workers=1, reload=False, proxy_headers=False)
    except (ValueError, FileExistsError, FileNotFoundError, ModuleNotFoundError) as exc:
        parser.exit(1, f"IRIS: {exc}\n")


if __name__ == "__main__":
    main()
