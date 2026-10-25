"""Run from the repository root: python demo.py. No Colab or FastAPI needed."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
DEMO_HOME = ROOT / '.local' / 'active_demo'
ACCESS = DEMO_HOME / 'access.json'


def settings():
    from backend.config import Settings, initialize
    if not ACCESS.exists():
        initialize(ACCESS)
    payload = json.loads(ACCESS.read_text(encoding='utf-8'))
    # Ignore the generic config state_dir: active demo state is always isolated.
    return Settings(DEMO_HOME / 'state', payload['role_keys'])


def main():
    parser = argparse.ArgumentParser(description='IRIS active, approval-gated synthetic SOC/GRC demonstration')
    parser.add_argument('command', nargs='?', default='serve', choices=('serve', 'keys', 'check'))
    parser.add_argument('--port', type=int, default=8010)
    args = parser.parse_args()
    try:
        if sys.version_info[:2] != (3, 12):
            raise ValueError('Use Python 3.12 and the pinned ML dependencies')
        if not 1 <= args.port <= 65535:
            raise ValueError('Port must be 1..65535')
        config = settings()
        if args.command == 'keys':
            print('Private local DEMO keys — do not share, commit, or screen-record:')
            for role, key in config.role_keys.items():
                print(f'{role}: {key}')
            return
        from demo_app.engine import DemoEngine
        engine = DemoEngine(config)
        if args.command == 'check':
            result = engine.status('admin')
            print(json.dumps({name: result[name] for name in ('exercise_id', 'counts', 'demo_only', 'external_writes')}, indent=2))
            print('Trusted models and synthetic data loaded. Run python -m unittest demo_app.tests.test_demo -v to test HTTP and approval writes.')
            return
        from demo_app.server import DemoServer
        with DemoServer(('127.0.0.1', args.port), engine) as server:
            print('IRIS ACTIVE DEMO — real local database changes, synthetic records only.', flush=True)
            for role in ('admin', 'soc', 'grc'):
                print(f'{role.upper()}: http://127.0.0.1:{args.port}/{role}', flush=True)
            print('In a SECOND private terminal run: python demo.py keys (use the same Python/venv executable)', flush=True)
            print('Use the separate role key in each tab. Admin analyzes; SOC/GRC approve their own changes.', flush=True)
            print('Keep this terminal open. Ctrl+C stops the server; approved changes remain saved.', flush=True)
            try:
                server.serve_forever(poll_interval=0.25)
            except KeyboardInterrupt:
                print('\nStopped. Demo state and audit history were preserved.')
    except ModuleNotFoundError as exc:
        parser.exit(1, f'Missing dependency {exc.name}. Install: python -m pip install -r IRIS_Models_v2/requirements.txt\n')
    except (ValueError, OSError) as exc:
        parser.exit(1, f'IRIS demo: {exc}\n')


if __name__ == '__main__':
    main()
