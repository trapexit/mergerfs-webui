#!/usr/bin/env python3
"""Exercise optional update authentication and same-PID restart without GitHub."""

import hashlib
import json
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request


def request(base, method, payload=None, password=None, route='/update',
            raw_body=None, timeout=2):
    headers = {'Content-Type': 'application/json'}
    if password is not None:
        headers['Authorization'] = 'Bearer ' + password
    body = raw_body.encode() if raw_body is not None else (
        json.dumps(payload).encode() if payload is not None else None)
    req = urllib.request.Request(base + route, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


def serve(binary, args, check, host='127.0.0.1'):
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1', 0))
        port = reserved.getsockname()[1]
    base = f'http://127.0.0.1:{port}'
    command = [str(binary), '--port', str(port), *args]
    if host is not None:
        command[1:1] = ['--host', host]
    server = subprocess.Popen(command, stdout=subprocess.DEVNULL,
                              stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 10
        while True:
            if server.poll() is not None:
                raise AssertionError('update test server exited before readiness')
            try:
                with urllib.request.urlopen(base + '/auth', timeout=2):
                    break
            except urllib.error.URLError:
                if time.monotonic() >= deadline:
                    raise AssertionError('update test server did not become ready')
                time.sleep(0.05)
        check(base, server)
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()


def auth(base):
    with urllib.request.urlopen(base + '/auth', timeout=2) as response:
        return json.load(response)

MERGERFS_STATUS_KEYS = {
    'state', 'path', 'version', 'manager', 'package', 'static_version',
    'in_place_allowed', 'static_install_allowed', 'warnings',
}
MERGERFS_ROUTE = '/mergerfs/update'


def mergerfs_status(base, password=None):
    status, result = request(base, 'GET', password=password, route='/mergerfs/status',
                             timeout=30)
    assert status == 200, (status, result)
    assert set(result) == MERGERFS_STATUS_KEYS, result
    assert result['state'] in ('missing', 'package', 'unmanaged', 'unknown'), result
    assert all(isinstance(result[key], str) for key in (
        'state', 'path', 'version', 'manager', 'package', 'static_version')), result
    assert isinstance(result['in_place_allowed'], bool), result
    assert isinstance(result['static_install_allowed'], bool), result
    assert isinstance(result['warnings'], list), result
    assert all(isinstance(warning, str) for warning in result['warnings']), result


def invalid_mergerfs_requests(base, password=None):
    selected = {'tag': '2.42.0', 'digest': 'a' * 64, 'target': 'existing'}
    invalid = [
        {}, [], None, {'tag': '2.42.0', 'digest': 'a' * 64},
        {**selected, 'extra': 'ignored'},
        {**selected, 'tag': '../unsafe'}, {**selected, 'tag': 42},
        {**selected, 'digest': 'not-a-digest'},
        {**selected, 'digest': 'A' * 64}, {**selected, 'digest': None},
        {**selected, 'target': 'invalid'}, {**selected, 'target': False},
    ]
    for payload in invalid:
        status, result = request(base, 'POST', payload, password, MERGERFS_ROUTE,
                                 raw_body='null' if payload is None else None)
        assert status == 400 and 'error' in result, (status, payload, result)
    for raw_body in ('{not-json',
                     '{"tag":"2.42.0","tag":"other","digest":"' + 'a' * 64 +
                     '","target":"static"}'):
        status, result = request(base, 'POST', password=password,
                                 route=MERGERFS_ROUTE, raw_body=raw_body)
        assert status == 400 and 'error' in result, (status, raw_body, result)


def restart_and_wait(base, server, password=None, updates_enabled=True):
    initial = auth(base)['instance_id']
    status, result = request(base, 'POST', password=password, route='/restart')
    assert status == 202 and result == {'result': 'restarting'}, (status, result)
    deadline = time.monotonic() + 10
    while True:
        assert server.poll() is None, 'restart exited instead of re-execing'
        try:
            current = auth(base)
            if current['instance_id'] != initial:
                break
        except urllib.error.URLError:
            pass
        if time.monotonic() >= deadline:
            raise AssertionError('same-PID restart did not become ready')
        time.sleep(0.05)
    assert current['updates_enabled'] is updates_enabled, current
    assert server.poll() is None


def verify_executable_relocation(binary, root):
    location = root / 'original-location'
    location.mkdir()
    installed = location / 'webui'
    shutil.copy2(binary, installed)
    relocated = root / 'relocated-location'
    moved = relocated / 'webui (deleted)'

    def check(base, server):
        assert auth(base)['updates_enabled'] is True
        location.rename(relocated)
        (relocated / 'webui').rename(moved)
        restart_and_wait(base, server)
        assert moved.is_file() and not location.exists()

        replacement = relocated / 'replacement'
        shutil.copy2(binary, replacement)
        replacement.replace(moved)
        restart_and_wait(base, server)
        assert moved.is_file() and not replacement.exists()

    serve(installed, [], check)


def verify(binary):
    with tempfile.TemporaryDirectory(prefix='mergerfs-update-test-') as directory:
        root = Path(directory)
        installed = root / 'mergerfs-webui'
        shutil.copy2(binary, installed)
        password_file = root / 'password'
        password_file.write_text('test-update-password\n')
        before = hashlib.sha256(installed.read_bytes()).hexdigest()

        def default_loopback(base, server):
            assert auth(base)['password_required'] is False
            port = int(base.rsplit(':', 1)[1])
            with socket.socket() as other_loopback:
                other_loopback.settimeout(2)
                assert other_loopback.connect_ex(('127.0.0.2', port)) != 0, (
                    'default listener accepts connections outside 127.0.0.1')
            assert server.poll() is None

        serve(installed, [], default_loopback, host=None)

        def open_access(base, server):
            first = auth(base)
            assert first['password_required'] is False
            assert first['updates_enabled'] is True
            port = int(base.rsplit(':', 1)[1])
            with socket.socket() as other_loopback:
                other_loopback.settimeout(2)
                assert other_loopback.connect_ex(('127.0.0.2', port)) == 0, (
                    'explicit wildcard host does not accept other local addresses')
            mergerfs_status(base)
            invalid_mergerfs_requests(base)
            for payload in ({'tag': '../other', 'digest': '0' * 64}, {}):
                status, _ = request(base, 'POST', payload)
                assert status == 400, (status, payload)
            restart_and_wait(base, server)

        serve(installed, [], open_access, host='0.0.0.0')

        def protected(base, server):
            first = auth(base)
            assert first['updates_enabled'] is True
            for password in (None, 'wrong-password'):
                for route in ('/mergerfs/status', MERGERFS_ROUTE):
                    status, result = request(base, 'GET', password=password, route=route)
                    assert status == 401 and 'error' in result, (status, route, result)
                for payload in ({}, {'tag': '2.42.0', 'digest': 'a' * 64,
                                    'target': 'existing'}):
                    status, result = request(base, 'POST', payload, password, MERGERFS_ROUTE)
                    assert status == 401 and 'error' in result, (status, result)
            status, result = request(base, 'POST', route=MERGERFS_ROUTE,
                                     raw_body='{not-json')
            assert status == 401 and 'error' in result, (status, result)
            mergerfs_status(base, 'test-update-password')
            invalid_mergerfs_requests(base, 'test-update-password')
            status, _ = request(base, 'GET')
            assert status == 401, status
            status, _ = request(base, 'POST', {'tag': '0.9', 'digest': '0' * 64})
            assert status == 401, status
            status, _ = request(base, 'POST', route='/restart')
            assert status == 401, status
            for payload in ({'tag': '../other', 'digest': '0' * 64},
                            {'tag': '0.9', 'digest': 'invalid'}, {}):
                status, _ = request(base, 'POST', payload, 'test-update-password')
                assert status == 400, (status, payload)

            mode = installed.stat().st_mode & 0o777
            installed.chmod(mode & ~0o111)
            try:
                status, _ = request(base, 'POST', password='test-update-password',
                                    route='/restart')
                assert status == 403, status
                assert auth(base)['instance_id'] == first['instance_id']
            finally:
                installed.chmod(mode)

            restart_and_wait(base, server, 'test-update-password')

        serve(installed, ['--password-file', str(password_file)], protected,
              host='0.0.0.0')
        hardlinked = root / 'hardlinked-webui'
        shutil.copy2(binary, hardlinked)
        (root / 'second-link').hardlink_to(hardlinked)

        def updater_unavailable(base, server):
            first = auth(base)
            assert first['password_required'] is False
            assert first['updates_enabled'] is False
            assert request(base, 'GET') == (200, {'enabled': False})
            mergerfs_status(base)
            invalid_mergerfs_requests(base)
            status, _ = request(base, 'POST', {'tag': '0.9', 'digest': '0' * 64})
            assert status == 422, status
            restart_and_wait(base, server, updates_enabled=False)

        serve(hardlinked, [], updater_unavailable, host='0.0.0.0')
        verify_executable_relocation(binary, root)
        assert hashlib.sha256(installed.read_bytes()).hexdigest() == before
        print('update and mergerfs optional authentication, validation, and restart integration: passed')


if __name__ == '__main__':
    verify(Path(sys.argv[1] if len(sys.argv) > 1 else 'build/mergerfs-webui').resolve())
