# IRIS EXPLAIN: File purpose: CLI for the earlier FastAPI prototype: initialize credentials, check dependencies, run core smoke
# IRIS EXPLAIN: inference, or serve on loopback.
# IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string so
# IRIS EXPLAIN: its value does not change.
"""Run from the repository root: python -m backend <command>."""
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import argparse to parse explicit command-line options and enforce allowed choices.
import argparse
# IRIS EXPLAIN: Import importlib.util to use the importlib support module.
import importlib.util
# IRIS EXPLAIN: Import json to encode and decode structured finite JSON payloads.
import json
# IRIS EXPLAIN: Import sys to inspect the Python version or select the same executable/import path.
import sys
# IRIS EXPLAIN: Import Path from pathlib to resolve server-owned paths without trusting uploaded filenames.
from pathlib import Path

# IRIS EXPLAIN: Import CONFIG, ROOT, Settings, initialize from .config to reuse the shared project contract/implementation
# IRIS EXPLAIN: rather than duplicate it.
from .config import CONFIG, ROOT, Settings, initialize


# IRIS EXPLAIN: Function main: Parse the existing command-line choices and dispatch the operations documented for this module:
# IRIS EXPLAIN: CLI for the earlier FastAPI prototype: initialize credentials, check dependencies, run core smoke inference, or
# IRIS EXPLAIN: serve on loopback.
def main():
    # IRIS EXPLAIN: Store the result of argparse.ArgumentParser(description='IRIS local shadow-backend prototype') in parser;
    # IRIS EXPLAIN: later lines use this named result.
    parser = argparse.ArgumentParser(description="IRIS local shadow-backend prototype")
    # IRIS EXPLAIN: Store the result of parser.add_subparsers(dest='command', required=True) in commands; later lines use this
    # IRIS EXPLAIN: named result.
    commands = parser.add_subparsers(dest="command", required=True)
    # IRIS EXPLAIN: Call commands.add_parser('init', help='Generate local role keys once; never commit .local'): register the
    # IRIS EXPLAIN: stated CLI subcommand.
    commands.add_parser("init", help="Generate local role keys once; never commit .local")
    # IRIS EXPLAIN: Call commands.add_parser('keys', help='Print your local role keys; do not share or screen-record them'):
    # IRIS EXPLAIN: register the stated CLI subcommand.
    commands.add_parser("keys", help="Print your local role keys; do not share or screen-record them")
    # IRIS EXPLAIN: Call commands.add_parser('check', help='Check dependencies and load the pinned user model'): register the
    # IRIS EXPLAIN: stated CLI subcommand.
    commands.add_parser("check", help="Check dependencies and load the pinned user model")
    # IRIS EXPLAIN: Store the result of commands.add_parser('smoke', help='Run the actual model adapter and SQLite path without
    # IRIS EXPLAIN: HTTP') (register the stated CLI subcommand) in smoke; later lines use this named result.
    smoke = commands.add_parser("smoke", help="Run the actual model adapter and SQLite path without HTTP")
    # IRIS EXPLAIN: Call smoke.add_argument('--state', type=Path, default=ROOT / '.local/smoke'): declare the existing CLI
    # IRIS EXPLAIN: option and its type/default/validation.
    smoke.add_argument("--state", type=Path, default=ROOT / ".local/smoke")
    # IRIS EXPLAIN: Store the result of commands.add_parser('serve', help='Start one local Uvicorn worker on 127.0.0.1')
    # IRIS EXPLAIN: (register the stated CLI subcommand) in serve; later lines use this named result.
    serve = commands.add_parser("serve", help="Start one local Uvicorn worker on 127.0.0.1")
    # IRIS EXPLAIN: Call serve.add_argument('--port', type=int, default=8000): declare the existing CLI option and its
    # IRIS EXPLAIN: type/default/validation.
    serve.add_argument("--port", type=int, default=8000)
    # IRIS EXPLAIN: Store the result of parser.parse_args() (parse and validate the supplied CLI arguments) in args; later lines
    # IRIS EXPLAIN: use this named result.
    args = parser.parse_args()
    # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally blocks
    # IRIS EXPLAIN: decide fallback and cleanup.
    try:
        # IRIS EXPLAIN: Enter this branch only when args.command == 'init'.
        if args.command == "init":
            # IRIS EXPLAIN: Call print(f'Created {initialize()}. Run python -m backend keys to view the three role keys
            # IRIS EXPLAIN: privately.') using the existing explicit arguments.
            print(f"Created {initialize()}. Run python -m backend keys to view the three role keys privately.")
        # IRIS EXPLAIN: Check this alternative branch when args.command == 'keys'.
        elif args.command == "keys":
            # IRIS EXPLAIN: Store the result of Settings.load() in settings; later lines use this named result.
            settings = Settings.load()
            # IRIS EXPLAIN: Iterate settings.role_keys.items(), binding each item to (role, key); process only the existing
            # IRIS EXPLAIN: observed/fixture collection.
            for role, key in settings.role_keys.items():
                # IRIS EXPLAIN: Call print(f'{role}: {key}') using the existing explicit arguments.
                print(f"{role}: {key}")
        # IRIS EXPLAIN: Check this alternative branch when args.command == 'check'.
        elif args.command == "check":
            # IRIS EXPLAIN: Store the comprehension [name for name in ('fastapi', 'uvicorn', 'httpx', 'python_multipart') if
            # IRIS EXPLAIN: importlib.util.find_spec(name) is None] in missing; later lines use this named result.
            missing = [name for name in ("fastapi", "uvicorn", "httpx", "python_multipart") if importlib.util.find_spec(name) is None]
            # IRIS EXPLAIN: Enter this branch only when missing.
            if missing:
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Missing web dependencies: ' +
                # IRIS EXPLAIN: ', '.join(missing) + '; install requirements-backend.txt'); the caller's existing boundary
                # IRIS EXPLAIN: determines rollback or the HTTP diagnostic.
                raise ValueError("Missing web dependencies: " + ", ".join(missing) + "; install requirements-backend.txt")
            # IRIS EXPLAIN: Import ModelAdapter from .model_adapter to reuse the shared project contract/implementation rather
            # IRIS EXPLAIN: than duplicate it.
            from .model_adapter import ModelAdapter
            # IRIS EXPLAIN: Call print(json.dumps(ModelAdapter().status(), indent=2)) using the existing explicit arguments.
            print(json.dumps(ModelAdapter().status(), indent=2))
            # IRIS EXPLAIN: Call print('Dependencies/model load checked. This is not an HTTP test: run the HTTP test suite
            # IRIS EXPLAIN: next.') using the existing explicit arguments.
            print("Dependencies/model load checked. This is not an HTTP test: run the HTTP test suite next.")
        # IRIS EXPLAIN: Check this alternative branch when args.command == 'smoke'.
        elif args.command == "smoke":
            # IRIS EXPLAIN: Import Engine from .core to reuse the shared project contract/implementation rather than duplicate
            # IRIS EXPLAIN: it.
            from .core import Engine
            # IRIS EXPLAIN: Store the comprehension {r: 'local-smoke-only-' + r + '-' * 40 for r in ('admin', 'soc', 'grc')} in
            # IRIS EXPLAIN: keys; later lines use this named result.
            keys = {r: "local-smoke-only-" + r + "-" * 40 for r in ("admin", "soc", "grc")}
            # IRIS EXPLAIN: Store the result of Engine(Settings(args.state, keys)) in engine; later lines use this named result.
            engine = Engine(Settings(args.state, keys))
            # IRIS EXPLAIN: Store the result of engine.sample('admin') in result; later lines use this named result.
            result = engine.sample("admin")
            # IRIS EXPLAIN: Call print(json.dumps({k: result[k] for k in ('run_id', 'status', 'sessions', 'shadow_class_counts',
            # IRIS EXPLAIN: 'model_sha256', 'reused_existing_run', 'training_labels_read'... using the existing explicit
            # IRIS EXPLAIN: arguments.
            print(json.dumps({k: result[k] for k in ("run_id", "status", "sessions", "shadow_class_counts", "model_sha256", "reused_existing_run", "training_labels_read", "automatic_execution", "official_risk_register_write")}, indent=2))
        # IRIS EXPLAIN: Handle the alternative to the preceding condition/loop exactly as originally defined.
        else:
            # IRIS EXPLAIN: Enter this branch only when sys.version_info[:2] != (3, 12).
            if sys.version_info[:2] != (3, 12):
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Use Python 3.12, matching the
                # IRIS EXPLAIN: documented model environment'); the caller's existing boundary determines rollback or the HTTP
                # IRIS EXPLAIN: diagnostic.
                raise ValueError("Use Python 3.12, matching the documented model environment")
            # IRIS EXPLAIN: Enter this branch only when not 1 <= args.port <= 65535.
            if not 1 <= args.port <= 65535:
                # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Invalid port'); the caller's
                # IRIS EXPLAIN: existing boundary determines rollback or the HTTP diagnostic.
                raise ValueError("Invalid port")
            # IRIS EXPLAIN: Call Settings.load() using the existing explicit arguments.
            Settings.load()
            # IRIS EXPLAIN: Import uvicorn to use the uvicorn support module.
            import uvicorn
            # IRIS EXPLAIN: Call uvicorn.run('backend.app:create_app', factory=True, host='127.0.0.1', port=args.port,
            # IRIS EXPLAIN: workers=1, reload=False, proxy_headers=False) using the existing explicit arguments.
            uvicorn.run("backend.app:create_app", factory=True, host="127.0.0.1", port=args.port,
                        # IRIS EXPLAIN: Continue the surrounding call, schema/list, or comprehension with these existing
                        # IRIS EXPLAIN: arguments/items: workers=1, reload=False, proxy_headers=False).
                        workers=1, reload=False, proxy_headers=False)
    # IRIS EXPLAIN: Catch (ValueError, FileExistsError, FileNotFoundError, ModuleNotFoundError) as exc; execute the existing
    # IRIS EXPLAIN: error/fallback path rather than silently treating it as success.
    except (ValueError, FileExistsError, FileNotFoundError, ModuleNotFoundError) as exc:
        # IRIS EXPLAIN: Call parser.exit(1, f'IRIS: {exc}\n'): stop with the existing status and diagnostic.
        parser.exit(1, f"IRIS: {exc}\n")


# IRIS EXPLAIN: Run the CLI/test entry point only when this file is executed directly, not when another module imports it.
if __name__ == "__main__":
    # IRIS EXPLAIN: Call main() using the existing explicit arguments.
    main()
