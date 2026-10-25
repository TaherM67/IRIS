# IRIS EXPLAIN: File purpose: Active examiner-demo launcher: isolated demo keys/state, the existing saved models, and the
# IRIS EXPLAIN: loopback server serving Admin/SOC/GRC dashboards.
# IRIS EXPLAIN: Existing documentation/literal text below is kept exactly as written; the explanation is outside the string so
# IRIS EXPLAIN: its value does not change.
"""Run from the repository root: python demo.py. No Colab or FastAPI needed."""
# IRIS EXPLAIN: Keep type annotations unevaluated at definition time; this does not add a model feature or change runtime
# IRIS EXPLAIN: settings.
from __future__ import annotations

# IRIS EXPLAIN: Import argparse to parse explicit command-line options and enforce allowed choices.
import argparse
# IRIS EXPLAIN: Import json to encode and decode structured finite JSON payloads.
import json
# IRIS EXPLAIN: Import sys to inspect the Python version or select the same executable/import path.
import sys
# IRIS EXPLAIN: Import Path from pathlib to resolve server-owned paths without trusting uploaded filenames.
from pathlib import Path

# IRIS EXPLAIN: Store Path(__file__).resolve().parent in ROOT; later lines use this named result.
ROOT = Path(__file__).resolve().parent
# IRIS EXPLAIN: Store the computed value ROOT / '.local' / 'active_demo' in DEMO_HOME; later lines use this named result.
DEMO_HOME = ROOT / '.local' / 'active_demo'
# IRIS EXPLAIN: Store the computed value DEMO_HOME / 'access.json' in ACCESS; later lines use this named result.
ACCESS = DEMO_HOME / 'access.json'


# IRIS EXPLAIN: Function settings: Create/reopen separate demo keys, then force the active demo database into its own isolated
# IRIS EXPLAIN: .local/active_demo/state directory.
def settings(create=True):
    """Reopen private demo credentials; doctor never initializes missing keys."""
    # IRIS EXPLAIN: Import Settings, initialize from backend.config to reuse the shared project contract/implementation rather
    # IRIS EXPLAIN: than duplicate it.
    from backend.config import Settings, initialize
    # IRIS EXPLAIN: Enter this branch only when not ACCESS.exists().
    if not ACCESS.exists():
        if not create:
            raise ValueError('No demo access file in this folder. Start python demo.py first, then run doctor in a second terminal.')
        # IRIS EXPLAIN: Call initialize(ACCESS) using the existing explicit arguments.
        initialize(ACCESS)
    # IRIS EXPLAIN: Store the result of json.loads(ACCESS.read_text(encoding='utf-8-sig')) (decode the existing JSON text) in
    # IRIS EXPLAIN: payload; later lines use this named result.
    # Windows editors can add a UTF-8 BOM; tolerate it without rewriting keys.
    payload = json.loads(ACCESS.read_text(encoding='utf-8-sig'))
    if not isinstance(payload, dict) or not isinstance(payload.get('role_keys'), dict):
        raise ValueError('Invalid demo access file. Restore your existing .local/active_demo/access.json; do not delete your database.')
    # Ignore the generic config state_dir: active demo state is always isolated.
    # IRIS EXPLAIN: Return the result of Settings(DEMO_HOME / 'state', payload['role_keys']) to the caller; this ends the
    # IRIS EXPLAIN: current function path.
    return Settings(DEMO_HOME / 'state', payload['role_keys'])


# IRIS EXPLAIN: Function main: Parse the existing command-line choices and dispatch the operations documented for this module:
# IRIS EXPLAIN: Active examiner-demo launcher: isolated demo keys/state, the existing saved models, and the loopback server
# IRIS EXPLAIN: serving Admin/SOC/GRC dashboards.
def main():
    # IRIS EXPLAIN: Store the result of argparse.ArgumentParser(description='IRIS active, approval-gated synthetic SOC/GRC
    # IRIS EXPLAIN: demonstration') in parser; later lines use this named result.
    parser = argparse.ArgumentParser(description='IRIS active, approval-gated synthetic SOC/GRC demonstration')
    # IRIS EXPLAIN: Declare the serve, keys, check and read-only doctor commands:
    # IRIS EXPLAIN: The default serves the existing saved models, not new training.
    parser.add_argument('command', nargs='?', default='serve', choices=('serve', 'keys', 'check', 'doctor'))
    # IRIS EXPLAIN: Call parser.add_argument('--port', type=int, default=8010): declare the existing CLI option and its
    # IRIS EXPLAIN: type/default/validation.
    parser.add_argument('--port', type=int, default=8010)
    parser.add_argument('--role', choices=('admin', 'soc', 'grc'), help='Print only this role with the keys command')
    # IRIS EXPLAIN: Store the result of parser.parse_args() (parse and validate the supplied CLI arguments) in args; later lines
    # IRIS EXPLAIN: use this named result.
    args = parser.parse_args()
    if args.role and args.command != 'keys':
        parser.error('--role is only used with the keys command')
    # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally blocks
    # IRIS EXPLAIN: decide fallback and cleanup.
    try:
        # IRIS EXPLAIN: Enter this branch only when sys.version_info[:2] != (3, 12).
        if sys.version_info[:2] != (3, 12):
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Use Python 3.12 and the pinned ML
            # IRIS EXPLAIN: dependencies'); the caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError('Use Python 3.12 and the pinned ML dependencies')
        # IRIS EXPLAIN: Enter this branch only when not 1 <= args.port <= 65535.
        if not 1 <= args.port <= 65535:
            # IRIS EXPLAIN: Stop this invalid/unauthorized/stale path by raising ValueError('Port must be 1..65535'); the
            # IRIS EXPLAIN: caller's existing boundary determines rollback or the HTTP diagnostic.
            raise ValueError('Port must be 1..65535')
        # Reuse existing settings; doctor is deliberately forbidden to create keys.
        config = settings(create=args.command != 'doctor')
        from demo_app.access import access_profile, inspect_access
        # Diagnose access before importing/initializing the ML engine. Only safe
        # result strings are printed; the diagnostic never prints a role token.
        if args.command == 'doctor':
            result = inspect_access(config, args.port)
            print('IRIS access check (no keys or records are printed):')
            for check in result['checks']:
                print(f'  {check}')
            if not result['ok']:
                parser.exit(1, 'Access check failed. Follow the messages above; do not delete .local.\n')
            print('All three roles can sign in. Reload the browser with Ctrl+F5.')
            return
        # IRIS EXPLAIN: Enter this branch only when args.command == 'keys'.
        if args.command == 'keys':
            # IRIS EXPLAIN: Call print('Private local DEMO keys — do not share, commit, or screen-record:') using the existing
            # IRIS EXPLAIN: explicit arguments.
            print('Private local DEMO keys — do not share, commit, or screen-record:')
            print(f'Access file: {ACCESS}')
            print(f'Key profile: {access_profile(config.role_keys)} (must match the sign-in page)')
            # IRIS EXPLAIN: Iterate config.role_keys.items(), binding each item to (role, key); process only the existing
            # IRIS EXPLAIN: observed/fixture collection.
            for role, key in config.role_keys.items():
                if args.role and role != args.role:
                    continue
                # IRIS EXPLAIN: Call print(f'{role}: {key}') using the existing explicit arguments.
                print(f'{role}: {key}')
            # IRIS EXPLAIN: Exit this function now without an additional result; do not continue into the remaining branch.
            return
        # IRIS EXPLAIN: Import DemoEngine from demo_app.engine to reuse the shared project contract/implementation rather than
        # IRIS EXPLAIN: duplicate it.
        from demo_app.engine import DemoEngine
        # IRIS EXPLAIN: Store the result of DemoEngine(config) in engine; later lines use this named result.
        engine = DemoEngine(config)
        # IRIS EXPLAIN: Enter this branch only when args.command == 'check'.
        if args.command == 'check':
            # IRIS EXPLAIN: Store the result of engine.status('admin') in result; later lines use this named result.
            result = engine.status('admin')
            # IRIS EXPLAIN: Call print(json.dumps({name: result[name] for name in ('exercise_id', 'counts', 'demo_only',
            # IRIS EXPLAIN: 'external_writes')}, indent=2)) using the existing explicit arguments.
            print(json.dumps({name: result[name] for name in ('exercise_id', 'counts', 'demo_only', 'external_writes')}, indent=2))
            # IRIS EXPLAIN: Call print('Trusted models and synthetic data loaded. Run python -m unittest
            # IRIS EXPLAIN: demo_app.tests.test_demo -v to test HTTP and approval writes.') using the existing explicit
            # IRIS EXPLAIN: arguments.
            print('Trusted models and synthetic data loaded. Run python -m unittest demo_app.tests.test_demo -v to test HTTP and approval writes.')
            # IRIS EXPLAIN: Exit this function now without an additional result; do not continue into the remaining branch.
            return
        # IRIS EXPLAIN: Import DemoServer from demo_app.server to reuse the shared project contract/implementation rather than
        # IRIS EXPLAIN: duplicate it.
        from demo_app.server import DemoServer
        # IRIS EXPLAIN: Enter DemoServer(('127.0.0.1', args.port), engine) as server; its context manager supplies the existing
        # IRIS EXPLAIN: cleanup/transaction/expected-exception behavior.
        with DemoServer(('127.0.0.1', args.port), engine) as server:
            # IRIS EXPLAIN: Call print('IRIS ACTIVE DEMO — real local database changes, synthetic records only.', flush=True)
            # IRIS EXPLAIN: using the existing explicit arguments.
            print('IRIS ACTIVE DEMO — real local database changes, synthetic records only.', flush=True)
            print(f'Key profile: {access_profile(config.role_keys)} · access file: {ACCESS}', flush=True)
            # IRIS EXPLAIN: Iterate ('admin', 'soc', 'grc'), binding each item to role; process only the existing
            # IRIS EXPLAIN: observed/fixture collection.
            for role in ('admin', 'soc', 'grc'):
                # IRIS EXPLAIN: Call print(f'{role.upper()}: http://127.0.0.1:{args.port}/{role}', flush=True) using the
                # IRIS EXPLAIN: existing explicit arguments.
                print(f'{role.upper()}: http://127.0.0.1:{args.port}/{role}', flush=True)
            # IRIS EXPLAIN: Call print('In a SECOND private terminal run: python demo.py keys (use the same Python/venv
            # IRIS EXPLAIN: executable)', flush=True) using the existing explicit arguments.
            print('In a SECOND private terminal run: python demo.py keys (use the same Python/venv executable)', flush=True)
            # IRIS EXPLAIN: Call print('Use the separate role key in each tab. Admin analyzes; SOC/GRC approve their own
            # IRIS EXPLAIN: changes.', flush=True) using the existing explicit arguments.
            print('Use the separate role key in each tab. Admin analyzes; SOC/GRC approve their own changes.', flush=True)
            print('If sign-in fails: python demo.py doctor (same folder; add --port if changed).', flush=True)
            # IRIS EXPLAIN: Call print('Keep this terminal open. Ctrl+C stops the server; approved changes remain saved.',
            # IRIS EXPLAIN: flush=True) using the existing explicit arguments.
            print('Keep this terminal open. Ctrl+C stops the server; approved changes remain saved.', flush=True)
            # IRIS EXPLAIN: Attempt this operation inside the following explicit error boundary; the existing except/finally
            # IRIS EXPLAIN: blocks decide fallback and cleanup.
            try:
                # IRIS EXPLAIN: Call server.serve_forever(poll_interval=0.25): serve local requests until the demo is stopped.
                server.serve_forever(poll_interval=0.25)
            # IRIS EXPLAIN: Catch KeyboardInterrupt; execute the existing error/fallback path rather than silently treating it
            # IRIS EXPLAIN: as success.
            except KeyboardInterrupt:
                # IRIS EXPLAIN: Call print('\nStopped. Demo state and audit history were preserved.') using the existing
                # IRIS EXPLAIN: explicit arguments.
                print('\nStopped. Demo state and audit history were preserved.')
    # IRIS EXPLAIN: Catch ModuleNotFoundError as exc; execute the existing error/fallback path rather than silently treating it
    # IRIS EXPLAIN: as success.
    except ModuleNotFoundError as exc:
        # IRIS EXPLAIN: Call parser.exit(1, f'Missing dependency {exc.name}. Install: python -m pip install -r
        # IRIS EXPLAIN: IRIS_Models_v2/requirements.txt\n'): stop with the existing status and diagnostic.
        parser.exit(1, f'Missing dependency {exc.name}. Install: python -m pip install -r IRIS_Models_v2/requirements.txt\n')
    # IRIS EXPLAIN: Catch (ValueError, OSError) as exc; execute the existing error/fallback path rather than silently treating
    # IRIS EXPLAIN: it as success.
    except (ValueError, OSError) as exc:
        # IRIS EXPLAIN: Call parser.exit(1, f'IRIS demo: {exc}\n'): stop with the existing status and diagnostic.
        parser.exit(1, f'IRIS demo: {exc}\n')


# IRIS EXPLAIN: Run the CLI/test entry point only when this file is executed directly, not when another module imports it.
if __name__ == '__main__':
    # IRIS EXPLAIN: Call main() using the existing explicit arguments.
    main()
