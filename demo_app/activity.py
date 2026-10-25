"""Read-only, bounded activity for the Admin examiner window.

This is request telemetry, not a shell or a source of engine decisions. Never
record credentials, request bodies, review reasons, raw URLs or tracebacks.
The persistent database audit remains the proof of saved record changes.
"""
from collections import deque
from datetime import datetime, timezone
from threading import Lock
from time import monotonic


def utc_now():
    """Timestamp a real server event, explicitly in UTC."""
    return datetime.now(timezone.utc).isoformat(timespec='seconds')


class BackendActivity:
    """Thread-safe request start/outcome events for this server process only."""

    def __init__(self):
        self.lock = Lock()
        self.events = deque(maxlen=250)
        self.running = {}
        self.sequence = 0
        self.started_at = utc_now()
        self.events.append({'time': self.started_at, 'role': 'server', 'action': 'startup',
                            'state': 'ready', 'message': 'Local demo server ready.'})

    def start(self, role, action):
        """Record only fixed, server-selected action labels after authentication."""
        with self.lock:
            self.sequence += 1
            request_id = self.sequence
            self.running[request_id] = (monotonic(), role, action)
            self.events.append({'time': utc_now(), 'request_id': request_id,
                                'role': role, 'action': action, 'state': 'running',
                                'message': 'Backend command received; processing.'})
            return request_id

    def finish(self, request_id, status, response):
        """Log actual response outcomes, allowlisting numeric proof fields only."""
        with self.lock:
            task = self.running.pop(request_id, None)
            if task is None:
                return
            started, role, action = task
            successful = 200 <= status < 300
            message = 'Command completed.' if successful else f'Command rejected or failed (HTTP {status}); see the dashboard action message.'
            proof = {}
            if successful and isinstance(response, dict):
                for name in ('sessions', 'demo_records_written'):
                    value = response.get(name)
                    if type(value) is int:
                        proof[name] = value
                if 'demo_records_written' in proof:
                    message = f"Review completed; {proof['demo_records_written']} demo record(s) written."
                elif 'sessions' in proof:
                    message = f"Analysis completed; {proof['sessions']} sessions analyzed. Working records still require team approval."
            self.events.append({'time': utc_now(), 'request_id': request_id,
                                'role': role, 'action': action,
                                'state': 'completed' if successful else 'failed',
                                'http_status': status, 'elapsed_seconds': round(monotonic() - started, 3),
                                'message': message, **proof})

    def snapshot(self):
        """Copy bounded metadata; reads never create events or change records."""
        with self.lock:
            return {'started_at': self.started_at, 'active_commands': len(self.running),
                    'events': [dict(item) for item in self.events], 'process_only': True}
