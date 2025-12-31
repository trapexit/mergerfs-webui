#!/usr/bin/env python3
"""Exercise service API safety gates without touching systemd or installing a unit."""

import errno
import http.client
import json
import os
from pathlib import Path
import pwd
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.parse


def request(base, method, password=None, route='/service/install', body=None,
            source='127.0.0.1', extra_headers=None):
    headers = {'Content-Type': 'application/json'}
    if password is not None:
        headers['Authorization'] = 'Bearer ' + password
    if extra_headers:
        headers.update(extra_headers)
    url = urllib.parse.urlsplit(base)
    connection = http.client.HTTPConnection(
        url.hostname, url.port, timeout=2, source_address=(source, 0))
    try:
        connection.request(method, route, body=body, headers=headers)
        response = connection.getresponse()
        return response.status, json.load(response)
    finally:
        connection.close()


def serve(binary, args, check, host='127.0.0.1', client='127.0.0.1'):
    with socket.socket() as reserved:
        reserved.bind((host, 0))
        port = reserved.getsockname()[1]
    base = f'http://{client}:{port}'
    # Even if a safety gate regresses, a root-run test cannot install host units.
    def unprivileged():
        nobody = pwd.getpwnam('nobody')
        os.setgroups([])
        os.setgid(nobody.pw_gid)
        os.setuid(nobody.pw_uid)

    server = subprocess.Popen(
        [str(binary), '--host', host, '--port', str(port), *args],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        preexec_fn=unprivileged if os.geteuid() == 0 else None)
    try:
        deadline = time.monotonic() + 10
        while True:
            if server.poll() is not None:
                raise AssertionError('service test server exited before readiness')
            try:
                request(base, 'GET', route='/auth')
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise AssertionError('service test server did not become ready')
                time.sleep(0.05)
        check(base, server)
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()


def assert_denied(response, code):
    status, payload = response
    assert status == code, (status, payload)
    assert isinstance(payload.get('error', {}).get('msg'), str), payload


def install_body(enable_password, password=None, mode='install', port=8081):
    payload = {'enable_password': enable_password, 'mode': mode, 'port': port,
               'expected_executable': '/usr/local/bin/mergerfs-webui'}
    if password is not None:
        payload['password'] = password
    return json.dumps(payload).encode()


def invalid_install_bodies():
    base = {'enable_password': False, 'mode': 'install', 'port': 8081,
            'expected_executable': '/usr/local/bin/mergerfs-webui'}
    def invalid(**changes):
        return json.dumps({**base, **changes}).encode()
    return (
        b'', b'not json', json.dumps([]).encode(), json.dumps({}).encode(),
        json.dumps({'enable_password': False, 'port': 8081,
                    'expected_executable': base['expected_executable']}).encode(),
        json.dumps({key: value for key, value in base.items() if key != 'port'}).encode(),
        invalid(extra=1),
        invalid(password='not allowed'),
        invalid(enable_password=True),
        invalid(enable_password=True, password='short'),
        invalid(enable_password=True, password='A' * 33),
        invalid(enable_password=True, password='A' * 31 + '!'),
        invalid(enable_password='false'),
        invalid(enable_password=True, password=123),
        invalid(expected_executable=123),
        invalid(mode='unknown'),
        invalid(mode=123),
        invalid(port=0),
        invalid(port=65536),
        invalid(port=-1),
        invalid(port=1.5),
        invalid(port='8081'),
        invalid(port=True),
    )


def verify(binary):
    with tempfile.TemporaryDirectory(prefix='mergerfs-service-test-') as directory:
        root = Path(directory)
        if os.geteuid() == 0:
            root.chmod(0o755)  # Allow the unprivileged server to open its fixture.
        installed = root / 'mergerfs-webui'
        shutil.copy2(binary, installed)
        password_file = root / 'insecure-password'
        password_file.write_text('service-test-secret\n')
        password_file.chmod(0o644)  # Intentionally insecure: never suitable for a service unit.
        original_password = password_file.read_bytes()
        original_mode = password_file.stat().st_mode & 0o777

        def unauthenticated(base, server):
            assert request(base, 'GET', route='/auth')[1]['password_required'] is False
            status, payload = request(base, 'GET', route='/service/status')
            assert status == 200 and payload['bootstrap'] is True, (status, payload)
            assert payload['available'] is False and isinstance(payload['reason'], str), payload
            assert 'executable' in payload, payload
            assert payload['running_available'] is False and payload['running_reason'], payload
            assert payload['running_executable'] == str(installed), payload
            assert payload['unit_mode'] == '', payload
            assert payload['port'] == int(base.rsplit(':', 1)[1]), payload
            for body in invalid_install_bodies():
                assert_denied(request(base, 'POST', body=body), 400)
            assert_denied(request(base, 'POST', body=install_body(False)), 403)
            assert_denied(request(base, 'POST', body=install_body(False, port=1)), 403)
            assert_denied(request(base, 'POST', body=install_body(False, port=65535)), 403)
            assert_denied(request(base, 'POST',
                                  body=install_body(True, 'A' * 32)), 403)
            assert_denied(request(base, 'DELETE', route='/service', body=b'{}'), 400)
            # The empty stop request passes parsing, but cannot manage systemd as non-root.
            assert_denied(request(base, 'POST', route='/service/stop', body=b''), 403)
            assert_denied(request(base, 'POST', route='/service/stop'), 403)
            for body in (json.dumps({}).encode(), json.dumps([]).encode(),
                         json.dumps(None).encode(), b' ',
                         json.dumps({'unexpected': True}).encode()):
                assert_denied(request(base, 'POST', route='/service/stop', body=body), 400)
            assert_denied(request(base, 'POST', body=install_body(False, mode='running')), 403)
            assert server.poll() is None
            assert request(base, 'GET', route='/auth')[1]['password_required'] is False

        serve(installed, [], unauthenticated)

        # A source address in 127/8 is routed entirely over loopback, but only
        # 127.0.0.1 is trusted for unauthenticated bootstrap.
        def remote_bootstrap(base, server):
            status, payload = request(base, 'GET', route='/service/status',
                                      source='127.0.0.2')
            assert status == 200 and payload['bootstrap'] is True, (status, payload)
            assert payload['available'] is False, payload
            assert 'opening Setup at localhost' in payload['reason'], payload

            gates = (
                ('POST', '/service/install', b'not json',
                 'initial setup requires opening Setup at localhost on this machine'),
                ('DELETE', '/service', b'{}',
                 'removing an unauthenticated service requires opening Setup at localhost'),
                ('POST', '/service/stop', b'{}',
                 'stopping an unauthenticated service requires opening Setup at localhost'),
            )
            for method, route, invalid_body, reason in gates:
                # If the gate is bypassed, each malformed body returns 400
                # rather than reaching the unprivileged systemd checks.
                status, payload = request(base, method, route=route,
                                          body=invalid_body, source='127.0.0.2')
                assert status == 403 and payload['error']['msg'] == reason, (status, payload)
                for headers in ({'Host': f'untrusted.example:{base.rsplit(":", 1)[1]}'},
                                {'X-Forwarded-For': '127.0.0.1'},
                                {'Via': '1.1 proxy'},
                                {'Forwarded': 'for=127.0.0.1'}):
                    status, payload = request(base, method, route=route,
                                              body=invalid_body, extra_headers=headers)
                    assert status == 403 and payload['error']['msg'] == reason, (
                        headers, status, payload)
            assert server.poll() is None

        serve(installed, [], remote_bootstrap)

        def insecure_credential(base, server):
            assert request(base, 'GET', route='/auth')[1]['password_required'] is True
            for password in (None, 'wrong-password'):
                assert_denied(request(base, 'GET', password, '/service/status'), 401)
                assert_denied(request(base, 'POST', password, body=b''), 401)
                assert_denied(request(base, 'DELETE', password, '/service', body=b''), 401)
                assert_denied(request(base, 'POST', password, '/service/stop', body=b''), 401)
            # Authentication takes precedence even over an unexpected POST body.
            assert_denied(request(base, 'POST',
                                  body=json.dumps({'unexpected': True}).encode()), 401)
            assert_denied(request(base, 'POST', route='/service/stop',
                                  body=json.dumps({'unexpected': True}).encode()), 401)
            status, payload = request(base, 'GET', 'service-test-secret', '/service/status')
            assert status == 200 and payload['bootstrap'] is False, (status, payload)
            # The correct credential authenticates but cannot authorize an unsafe unit.
            for body in invalid_install_bodies():
                assert_denied(request(base, 'POST', 'service-test-secret', body=body), 400)
            assert_denied(request(base, 'POST', 'service-test-secret',
                                  body=install_body(True, 'A' * 32)), 400)
            assert_denied(request(base, 'POST', 'service-test-secret',
                                  body=install_body(False)), 403)
            assert_denied(request(base, 'DELETE', 'service-test-secret', '/service', body=b''), 403)
            assert_denied(request(base, 'POST', 'service-test-secret',
                                  '/service/stop', body=b''), 403)
            for body in (json.dumps({}).encode(), b'not json'):
                assert_denied(request(base, 'POST', 'service-test-secret',
                                      '/service/stop', body=body), 400)
            assert server.poll() is None
            assert_denied(request(base, 'GET', route='/service/status'), 401)

        serve(installed, ['--password-file', str(password_file)], insecure_credential)
        assert password_file.read_bytes() == original_password
        assert password_file.stat().st_mode & 0o777 == original_mode
        print('service API auth and unsafe-install guards: passed')


def verify_unit_writer(driver):
    with tempfile.TemporaryDirectory(prefix='mergerfs-unit-test-') as directory:
        units = Path(directory) / 'units'
        units.mkdir(mode=0o700)
        unit = units / 'mergerfs-webui.service'
        arguments = [str(driver), str(units), '/usr/local/bin/mergerfs-webui',
                     '127.0.0.1', '/etc/mergerfs-webui/password', 'default']

        def write(args=arguments):
            return subprocess.run(args, capture_output=True, text=True, check=False)

        first = write()
        assert first.returncode == 0 and first.stdout.strip() == 'created', first
        text = unit.read_text()
        assert unit.stat().st_mode & 0o777 == 0o644
        assert ('ExecStart=/usr/local/bin/mergerfs-webui --host 127.0.0.1'
                ' --port 8080 --password-file /etc/mergerfs-webui/password\n') in text
        assert '[Install]\nWantedBy=multi-user.target\n' in text
        assert write().stdout.strip() == 'unchanged'
        assert unit.read_text() == text
        conflicting = write([*arguments[:-1], 'other-port'])
        assert conflicting.returncode != 0 and unit.read_text() == text
        no_password = [*arguments[:4], 'none', arguments[5]]
        collision = write(no_password)
        assert collision.returncode != 0 and unit.read_text() == text, collision
        unit.unlink()
        first = write(no_password)
        assert first.returncode == 0 and first.stdout.strip() == 'created', first
        anonymous_text = unit.read_text()
        assert ('ExecStart=/usr/local/bin/mergerfs-webui --host 127.0.0.1'
                ' --port 8080\n') in anonymous_text
        assert '--password-file' not in anonymous_text
        assert unit.stat().st_mode & 0o777 == 0o644
        assert write(no_password).stdout.strip() == 'unchanged'
        assert unit.read_text() == anonymous_text
        for conflicting_args in (arguments, [*no_password[:-1], 'other-port']):
            collision = write(conflicting_args)
            assert collision.returncode != 0 and unit.read_text() == anonymous_text, collision
        unit.unlink()
        alternate = write([*no_password[:-1], 'other-port'])
        assert alternate.returncode == 0 and alternate.stdout.strip() == 'created', alternate
        assert ' --port 8081\n' in unit.read_text()

        unit.unlink()
        victim = Path(directory) / 'victim'
        victim.write_text('do not modify\n')
        unit.symlink_to(victim)
        assert write().returncode != 0
        assert victim.read_text() == 'do not modify\n'
        unit.unlink()

        injection = write([arguments[0], arguments[1], arguments[2],
                           'localhost\n[Service]\nExecStart=/bin/sh', arguments[4],
                           arguments[5]])
        assert injection.returncode != 0 and not unit.exists()
        print('sandbox systemd unit creation, collision and input guards: passed')

def verify_unit_removal(driver):
    with tempfile.TemporaryDirectory(prefix='mergerfs-unit-remove-test-') as directory:
        root = Path(directory)
        units = root / 'units'
        units.mkdir(mode=0o700)
        unit = units / 'mergerfs-webui.service'
        sibling = units / 'unrelated.service'
        sibling.write_bytes(b'leave this service intact\n')
        credential = root / 'password'
        credential.write_bytes(b'leave this credential intact\n')
        executable = root / 'binary'
        executable.write_bytes(b'leave this executable intact\n')
        args = [str(driver), str(units), '/usr/local/bin/mergerfs-webui',
                '127.0.0.1', '/etc/mergerfs-webui/password', 'default']

        def run(*arguments):
            return subprocess.run(arguments, capture_output=True, text=True, check=False)

        def refused(code):
            result = run(str(driver), 'remove', *args[1:])
            assert result.returncode == 1 and result.stderr.startswith(f'{-code}: '), result
            assert sibling.read_bytes() == b'leave this service intact\n'
            assert credential.read_bytes() == b'leave this credential intact\n'
            assert executable.read_bytes() == b'leave this executable intact\n'

        units.chmod(0o777)
        untrusted = run(str(driver), 'remove', *args[1:])
        assert untrusted.returncode == 1 and untrusted.stderr.startswith(
            f'{-errno.EACCES}: '), untrusted
        assert str(units) in untrusted.stderr, untrusted
        assert not unit.exists()
        units.chmod(0o700)

        refused(errno.ENOENT)
        assert run(*args).stdout.strip() == 'created'
        original = unit.read_bytes()
        sibling_stat = sibling.stat()
        unit_stat = unit.stat()
        mismatched = run(str(driver), 'remove', *args[1:4], 'none', 'default')
        assert mismatched.returncode == 1 and mismatched.stderr.startswith(
            f'{-errno.EEXIST}: '), mismatched
        assert unit.read_bytes() == original

        altered = run(str(driver), 'remove', *args[1:-1], 'other-port')
        assert altered.returncode == 1 and altered.stderr.startswith(f'{-errno.EEXIST}: ')
        assert unit.read_bytes() == original
        assert unit.stat().st_ino == unit_stat.st_ino
        unit.write_bytes(original.replace(b'RestartSec=2s', b'RestartSec=3s'))
        refused(errno.EEXIST)
        assert unit.exists()
        assert unit.stat().st_ino == unit_stat.st_ino
        unit.write_bytes(original)
        unit.chmod(0o666)
        refused(errno.EEXIST)
        unit.chmod(0o644)
        unit.unlink()
        unit.symlink_to(sibling)
        refused(errno.EEXIST)
        assert unit.is_symlink()
        unit.unlink()

        assert run(*args).stdout.strip() == 'created'
        linked = root / 'linked-unit'
        os.link(unit, linked)
        refused(errno.EEXIST)
        assert linked.read_bytes() == original
        linked.unlink()
        assert unit.read_bytes() == original
        assert unit.stat().st_mode & 0o777 == 0o644
        removed = run(str(driver), 'remove', *args[1:])
        assert removed.returncode == 0 and removed.stdout.strip() == 'removed', removed
        assert not unit.exists()
        refused(errno.ENOENT)
        no_password = [*args[:4], 'none', args[5]]
        assert run(*no_password).stdout.strip() == 'created'
        anonymous = unit.read_bytes()
        assert b'--password-file' not in anonymous
        assert run(*no_password).stdout.strip() == 'unchanged'
        mismatched = run(str(driver), 'remove', *args[1:])
        assert mismatched.returncode == 1 and mismatched.stderr.startswith(
            f'{-errno.EEXIST}: '), mismatched
        assert unit.read_bytes() == anonymous
        unit.write_bytes(anonymous.replace(b'RestartSec=2s', b'RestartSec=3s'))
        mismatch = run(str(driver), 'remove', *no_password[1:])
        assert mismatch.returncode == 1 and mismatch.stderr.startswith(
            f'{-errno.EEXIST}: '), mismatch
        assert unit.exists()
        unit.write_bytes(anonymous)
        removed = run(str(driver), 'remove', *no_password[1:])
        assert removed.returncode == 0 and removed.stdout.strip() == 'removed', removed
        assert not unit.exists()
        assert sibling.read_bytes() == b'leave this service intact\n'
        assert credential.read_bytes() == b'leave this credential intact\n'
        assert executable.read_bytes() == b'leave this executable intact\n'
        after = sibling.stat()
        assert (after.st_ino, after.st_mode, after.st_size, after.st_mtime_ns) == (
            sibling_stat.st_ino, sibling_stat.st_mode, sibling_stat.st_size, sibling_stat.st_mtime_ns)
        print('sandbox service removal and preservation guards: passed')



def verify_install_files(driver):
    with tempfile.TemporaryDirectory(prefix='mergerfs-install-files-test-') as directory:
        root = Path(directory)
        source = root / 'running-webui'
        shutil.copy2(driver, source)
        source.chmod(0o755)
        bin_dir = root / 'bin'
        bin_dir.mkdir(mode=0o700)
        destination = bin_dir / 'mergerfs-webui'
        def invoke(*args):
            return subprocess.run([str(driver), *map(str, args)],
                                  capture_output=True, text=True, check=False)

        def success(*args, expected='created'):
            result = invoke(*args)
            assert result.returncode == 0 and result.stdout.strip() == expected, result

        def denied(*args):
            result = invoke(*args)
            assert result.returncode != 0, result
        assert not destination.exists()

        success('stage', source, destination)
        assert destination.read_bytes() == source.read_bytes()
        assert destination.stat().st_mode & 0o7777 == 0o755
        assert destination.stat().st_uid == os.geteuid()
        success('stage', source, destination, expected='unchanged')
        assert destination.read_bytes() == source.read_bytes()
        previous_inode = destination.stat().st_ino
        destination.write_bytes(b'an older installed executable\n')
        destination.chmod(0o755)
        success('stage', source, destination)
        assert destination.read_bytes() == source.read_bytes()
        assert destination.stat().st_ino != previous_inode
        assert destination.stat().st_mode & 0o7777 == 0o755
        modified = bytearray(source.read_bytes())
        modified[0] ^= 1
        destination.write_bytes(modified)
        destination.chmod(0o755)
        previous_inode = destination.stat().st_ino
        success('stage', source, destination)
        assert destination.read_bytes() == source.read_bytes()
        assert destination.stat().st_ino != previous_inode
        units = root / 'units'
        units.mkdir(mode=0o700)
        success(str(units), destination, '127.0.0.1', 'none', 'default')
        assert f'ExecStart={destination} --host 127.0.0.1' in (
            units / 'mergerfs-webui.service').read_text()
        destination.unlink()
        victim = root / 'victim'
        victim.write_bytes(b'preserve me\n')
        destination.symlink_to(victim)
        denied('stage', source, destination)
        assert destination.is_symlink() and victim.read_bytes() == b'preserve me\n'
        destination.unlink()

        destination.write_bytes(source.read_bytes())
        destination.chmod(0o777)
        denied('stage', source, destination)
        assert destination.stat().st_mode & 0o777 == 0o777
        assert destination.read_bytes() == source.read_bytes()
        destination.unlink()

        unsafe_source = root / 'source-link'
        unsafe_source.symlink_to(source)
        denied('stage', unsafe_source, destination)
        assert not destination.exists()

        bin_link = root / 'bin-link'
        bin_link.symlink_to(bin_dir, target_is_directory=True)
        denied('stage', source, bin_link / 'mergerfs-webui')
        assert not destination.exists()
        linked = root / 'linked-executable'
        os.link(source, linked)
        os.link(source, destination)
        denied('stage', source, destination)
        assert destination.stat().st_ino == source.stat().st_ino
        destination.unlink()
        linked.unlink()
        source.chmod(0o777)
        untrusted = subprocess.run([str(source), 'trust-running'],
                                   capture_output=True, text=True, check=False)
        assert untrusted.returncode != 0 and 'root-owned regular files' in untrusted.stderr, untrusted

        credentials = root / 'credentials'
        secret = 'A' * 32
        success('password', credentials, secret)
        password = credentials / 'password'
        assert credentials.stat().st_mode & 0o777 == 0o700
        assert credentials.stat().st_uid == os.geteuid()
        assert password.stat().st_mode & 0o7777 == 0o600
        assert password.read_bytes() == secret.encode() + b'\n'
        original_inode = password.stat().st_ino
        success('password', credentials, secret, expected='unchanged')
        assert password.stat().st_ino == original_inode
        changed_secret = 'B' * 32
        success('password', credentials, changed_secret)
        assert password.read_bytes() == changed_secret.encode() + b'\n'
        assert password.stat().st_ino != original_inode
        assert password.stat().st_mode & 0o7777 == 0o600
        assert list(credentials.iterdir()) == [password]
        success('password', credentials, changed_secret, expected='unchanged')
        original = password.read_bytes()

        password.unlink()
        password.symlink_to(victim)
        denied('password', credentials, secret)
        assert password.is_symlink() and victim.read_bytes() == b'preserve me\n'
        password.unlink()

        password.write_bytes(original)
        password.chmod(0o644)
        denied('password', credentials, secret)
        assert password.read_bytes() == original
        assert password.stat().st_mode & 0o777 == 0o644
        password.unlink()

        credentials.chmod(0o777)
        denied('password', credentials, secret)
        assert not password.exists()
        credential_link = root / 'credentials-link'
        credential_link.symlink_to(credentials, target_is_directory=True)
        denied('password', credential_link, secret)
        assert not password.exists()
        print('sandbox executable and credential trust boundaries: passed')


if __name__ == '__main__':
    binary = Path(sys.argv[1] if len(sys.argv) > 1 else 'build/mergerfs-webui').resolve()
    driver = Path(sys.argv[2] if len(sys.argv) > 2 else 'build/test-service-install').resolve()
    verify(binary)
    verify_unit_writer(driver)
    verify_unit_removal(driver)
    verify_install_files(driver)
