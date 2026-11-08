"""Local account passwords and revocable, per-tab bearer sessions."""
from __future__ import annotations

from collections import deque
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import threading
import time

USERS_FILE = Path(__file__).resolve().parents[1] / '.local/active_demo/users.json'
ROLES = {'admin', 'soc', 'grc'}
SCRYPT = {'n': 32768, 'r': 8, 'p': 3, 'dklen': 32, 'maxmem': 64 * 1024 * 1024}
IDLE_SECONDS, LIFETIME_SECONDS = 1800, 28800


class AuthenticationError(Exception):
    def __init__(self, status, detail):
        self.status, self.detail = status, detail


def password_hash(password, salt):
    return hashlib.scrypt(password.encode('utf-8'), salt=salt, **SCRYPT)


def account_record(username, password, role):
    if not isinstance(username, str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,64}', username):
        raise ValueError('Username must contain 1..64 letters, numbers, dots, hyphens or underscores')
    if role not in ROLES or not isinstance(password, str) or not 8 <= len(password) <= 256:
        raise ValueError('Choose an existing role and a password of 8..256 characters')
    salt = secrets.token_bytes(16)
    return {'username': username, 'role': role, 'algorithm': 'scrypt-v1',
            'salt': salt.hex(), 'password_hash': password_hash(password, salt).hex()}


def write_accounts(path, records, *, create=True):
    path = Path(path)
    # Validate before persisting; never write a password in plaintext.
    AccountAuth(records)
    payload = json.dumps({'schema': 'iris-local-accounts-v1', 'users': records}, indent=2) + '\n'
    path.parent.mkdir(parents=True, exist_ok=True)
    if create:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
            stream.write(payload)
    else:
        temporary = path.with_name(path.name + '.' + secrets.token_hex(8) + '.tmp')
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, 'w', encoding='utf-8') as stream:
                stream.write(payload)
            temporary.replace(path)
        finally:
            temporary.unlink(missing_ok=True)


class AccountAuth:
    def __init__(self, records, *, clock=time.monotonic):
        self.users = {}
        for row in records:
            name = row['username']
            if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9._-]{1,64}', name)
                    or name.casefold() in self.users or row['role'] not in ROLES
                    or row['algorithm'] != 'scrypt-v1'
                    or len(bytes.fromhex(row['salt'])) != 16 or len(bytes.fromhex(row['password_hash'])) != 32):
                raise ValueError('Invalid or duplicate account record')
            self.users[name.casefold()] = dict(row)
        if not self.users:
            raise ValueError('At least one local sign-in account is required')
        self.clock, self.lock = clock, threading.Lock()
        self.sessions, self.failures, self.attempts = {}, {}, deque()

    @classmethod
    def load(cls, path=USERS_FILE):
        path = Path(path)
        if not path.is_file():
            raise ValueError('No local accounts configured. Run python -m demo_app.auth add --username NAME --role ROLE')
        payload = json.loads(path.read_text(encoding='utf-8'))
        if payload.get('schema') != 'iris-local-accounts-v1':
            raise ValueError('Unsupported local account format')
        return cls(payload['users'])

    def _prune(self, now):
        self.sessions = {key: row for key, row in self.sessions.items()
                         if now - row['created'] < LIFETIME_SECONDS and now - row['last_seen'] < IDLE_SECONDS}
        self.failures = {key: deque(t for t in times if now - t < 60)
                         for key, times in self.failures.items() if times and now - times[-1] < 60}
        while self.attempts and now - self.attempts[0] >= 60:
            self.attempts.popleft()

    def login(self, username, password, workspace):
        if (not isinstance(username, str) or not isinstance(password, str) or workspace not in ROLES
                or not 1 <= len(username.strip()) <= 64 or not 1 <= len(password) <= 256):
            raise AuthenticationError(401, 'Invalid username, password or selected workspace')
        name = username.strip().casefold()
        now = self.clock()
        with self.lock:
            self._prune(now)
            if len(self.attempts) >= 30 or len(self.failures.get(name, ())) >= 5:
                raise AuthenticationError(429, 'Too many sign-in attempts. Please wait one minute and try again.')
            self.attempts.append(now)
            self.failures.setdefault(name, deque()).append(now)
        row = self.users.get(name)
        comparison = row or next(iter(self.users.values()))
        valid = secrets.compare_digest(password_hash(password, bytes.fromhex(comparison['salt'])),
                                       bytes.fromhex(comparison['password_hash']))
        if row is None or not valid or row['role'] != workspace:
            raise AuthenticationError(401, 'Invalid username, password or selected workspace')
        token = secrets.token_urlsafe(32)
        with self.lock:
            now = self.clock()
            self._prune(now)
            if len(self.sessions) >= 128:
                raise AuthenticationError(429, 'Too many open sessions. Sign out of an unused dashboard first.')
            self.failures.pop(name, None)
            self.sessions[hashlib.sha256(token.encode()).hexdigest()] = {
                'username': row['username'], 'role': row['role'], 'created': now, 'last_seen': now}
        return {'access_token': token, 'token_type': 'Bearer', 'username': row['username'],
                'role': row['role'], 'expires_in': LIFETIME_SECONDS}

    def authenticate(self, token):
        if not isinstance(token, str) or not re.fullmatch(r'[A-Za-z0-9_-]{43}', token):
            raise AuthenticationError(401, 'Sign in with your username and password')
        key = hashlib.sha256(token.encode()).hexdigest()
        with self.lock:
            now = self.clock()
            self._prune(now)
            row = self.sessions.get(key)
            if row is None:
                raise AuthenticationError(401, 'Your session has ended. Please sign in again.')
            row['last_seen'] = now
            return {field: row[field] for field in ('username', 'role')}

    def logout(self, token):
        with self.lock:
            self.sessions.pop(hashlib.sha256(token.encode()).hexdigest(), None)


def main():
    import argparse
    import getpass
    parser = argparse.ArgumentParser(description='Maintain local demo sign-in accounts; restart the server after changes')
    parser.add_argument('command', choices=('add', 'reset-password'))
    parser.add_argument('--username', required=True)
    parser.add_argument('--role', choices=sorted(ROLES))
    args = parser.parse_args()
    records = list(AccountAuth.load().users.values()) if USERS_FILE.exists() else []
    existing = next((row for row in records if row['username'].casefold() == args.username.casefold()), None)
    if args.command == 'add' and (existing or not args.role):
        parser.error('For a new username, specify --role; existing accounts are not replaced')
    if args.command == 'reset-password' and not existing:
        parser.error('Account does not exist')
    password = getpass.getpass('New password: ')
    if password != getpass.getpass('Confirm password: '):
        parser.error('Passwords do not match')
    row = account_record(existing['username'] if existing else args.username, password,
                         existing['role'] if existing else args.role)
    records = [entry for entry in records if entry is not existing] + [row]
    write_accounts(USERS_FILE, records, create=not USERS_FILE.exists())
    print('Account saved. Restart the demo to apply the account change.')


if __name__ == '__main__':
    main()
