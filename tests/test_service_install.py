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


def install_body(password_mode='none', password=None, mode='install', port=8081,
                 host='127.0.0.1'):
    payload = {'password_mode': password_mode, 'mode': mode, 'host': host,
               'port': port, 'expected_executable': '/usr/local/bin/mergerfs-webui'}
    if password is not None:
        payload['password'] = password
    return json.dumps(payload).encode()


def invalid_install_bodies():
    base = json.loads(install_body())
    def invalid(**changes):
        return json.dumps({**base, **changes}).encode()
    return (
        b'', b'not json', json.dumps([]).encode(), json.dumps({}).encode(),
        *(json.dumps({key: value for key, value in base.items() if key != field}).encode()
          for field in base),
        invalid(extra=1), invalid(password='not allowed'),
        invalid(password_mode='current', password='not allowed'),
        invalid(password_mode='new'),
        invalid(password_mode='new', password=''),
        invalid(password_mode='new', password='A' * 129),
        invalid(password_mode='new', password='has space'),
        invalid(password_mode='new', password='control\n'),
        invalid(password_mode='new', password='non-ascii-é'),
        invalid(password_mode='new', password=123),
        invalid(password_mode='unknown'), invalid(password_mode=True),
        invalid(expected_executable=123),
        invalid(expected_executable='/tmp/injected\nExecStart=/bin/sh'),
        invalid(mode='unknown'), invalid(mode=123),
        invalid(host=123), invalid(host=''), invalid(host='x' * 2049),
        invalid(host='localhost\n[Service]'), invalid(host='host name'),
        invalid(host='$(command)'), invalid(host='host%name'),
        invalid(port=0), invalid(port=65536), invalid(port=-1),
        invalid(port=1.5), invalid(port='8081'), invalid(port=True),
    )


def verify(binary):
    with tempfile.TemporaryDirectory(prefix='mergerfs-service-test-') as directory:
        root = Path(directory)
        if os.geteuid() == 0:
            root.chmod(0o755)
        installed = root / 'mergerfs-webui'
        shutil.copy2(binary, installed)
        password_file = root / 'existing-password'
        password_file.write_text('service-test-secret\n')
        password_file.chmod(0o644)
        original_password = password_file.read_bytes()
        original_mode = password_file.stat().st_mode & 0o777

        def check(base, server, authenticated=False):
            token = 'service-test-secret' if authenticated else None
            if authenticated:
                for wrong in (None, 'wrong-password'):
                    for method, route in (
                            ('GET', '/service/status'), ('POST', '/service/install'),
                            ('DELETE', '/service'), ('POST', '/service/stop')):
                        assert_denied(request(base, method, wrong, route, body=b''), 401)
            for source in ('127.0.0.1', '127.0.0.2'):
                status, payload = request(base, 'GET', token, '/service/status', source=source)
                assert status == 200, (status, payload)
                assert payload['bootstrap'] is not authenticated, payload
                assert payload['available'] is False, payload
                assert payload['host'] == '127.0.0.1', payload
                assert payload['port'] == int(base.rsplit(':', 1)[1]), payload
                assert payload['password_mode'] == ('current' if authenticated else 'none')
                assert payload['password_file'] == (str(password_file) if authenticated else '')
                assert payload['running_available'] is True, payload
                assert payload['running_executable'] == str(installed), payload
                for body in invalid_install_bodies():
                    assert_denied(request(base, 'POST', token, body=body, source=source), 400)
                if not authenticated:
                    assert_denied(request(base, 'POST', token,
                                          body=install_body('current'), source=source), 400)
                for host in ('127.0.0.1', '0.0.0.0', 'localhost', '::', 'webui.example'):
                    for port in (1, 65535):
                        assert_denied(request(base, 'POST', token,
                                              body=install_body(host=host, port=port),
                                              source=source), 403)
                policies = [('none', None), ('new', '!'), ('new', '~' * 128)]
                if authenticated:
                    policies.append(('current', None))
                for mode in ('install', 'running'):
                    for policy, secret in policies:
                        assert_denied(request(base, 'POST', token,
                                              body=install_body(policy, secret, mode),
                                              source=source), 403)
                for method, route in (('DELETE', '/service'), ('POST', '/service/stop')):
                    assert_denied(request(base, method, token, route, body=b'{}', source=source), 400)
                    assert_denied(request(base, method, token, route, body=b'', source=source), 403)
                # Proxy headers no longer impose a service-only localhost gate.
                assert_denied(request(base, 'POST', token, body=b'not json', source=source,
                                      extra_headers={'Forwarded': 'for=127.0.0.1'}), 400)
                # Existing same-origin protections still apply to writes.
                assert_denied(request(base, 'POST', token, body=install_body(), source=source,
                                      extra_headers={'Origin': 'http://unrelated.invalid'}), 403)
            assert server.poll() is None
            assert request(base, 'GET', route='/auth')[1]['password_required'] is authenticated

        serve(installed, [], lambda base, server: check(base, server))
        serve(installed, ['--password-file', str(password_file)],
              lambda base, server: check(base, server, authenticated=True))
        assert password_file.read_bytes() == original_password
        assert password_file.stat().st_mode & 0o777 == original_mode
        print('service binding, independent authentication and request guards: passed')


def verify_unit_writer(driver):
    with tempfile.TemporaryDirectory(prefix='mergerfs-unit-test-') as directory:
        units = Path(directory) / 'units'
        units.mkdir(mode=0o700)
        unit = units / 'mergerfs-webui.service'
        arguments = [str(driver), str(units), '/usr/local/bin/mergerfs-webui',
                     '127.0.0.1', '/etc/mergerfs-webui/password', 'default']

        def write(args=arguments):
            return subprocess.run(args, capture_output=True, text=True, check=False)
        def run(*arguments):
            return subprocess.run(arguments, capture_output=True, text=True, check=False)

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

        # Any real port must work, not only the sentinel values the writer takes.
        unit.unlink()
        written = write([*no_password[:-1], '45231'])
        assert written.returncode == 0, written
        assert ' --port 45231\n' in unit.read_text()
        resourced = run(str(driver), 'replace', str(units),
                        '/usr/local/bin/mergerfs-webui', '127.0.0.1', 'none', '45231',
                        '/usr/local/bin/mergerfs-webui', '0.0.0.0', 'none', '45232')
        assert resourced.returncode == 0 and resourced.stdout.strip() == 'replaced', resourced
        assert ' --port 45232\n' in unit.read_text()
        assert run(str(driver), 'replace', str(units),
                   '/usr/local/bin/mergerfs-webui', '127.0.0.1', 'none', '45231',
                   '/usr/local/bin/mergerfs-webui', '0.0.0.0', 'none', 'same-port').returncode != 0

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

def verify_unit_inspection(driver):
    with tempfile.TemporaryDirectory(prefix='mergerfs-unit-inspect-test-') as directory:
        root = Path(directory)
        units = root / 'units'
        units.mkdir(mode=0o700)
        unit = units / 'mergerfs-webui.service'
        credential = root / 'existing-password'
        credential.write_bytes(b'existing-secret\n')
        executable = '/home/user/mergerfs-webui'

        def run(*args):
            return subprocess.run([str(driver), *map(str, args)],
                                  capture_output=True, text=True, check=False)

        assert run('inspect', units).stdout.strip() == 'absent'
        # Bindings, ports and existing credentials must survive inspection even
        # when they differ from the foreground server's configuration.
        for host, port, password in (
                ('0.0.0.0', 1, 'none'), ('127.0.0.1', 65535, credential),
                ('::', 8081, '/etc/mergerfs-webui/password'),
                ('webui.example', 8080, 'none')):
            result = run(units, executable, host, password, port)
            assert result.returncode == 0, result
            inspected = run('inspect', units)
            assert inspected.returncode == 0, inspected
            assert inspected.stdout.rstrip('\n').split('\t') == [
                executable, host, str(port), '' if password == 'none' else str(password)]
            removed = run('remove-installed', units)
            assert removed.returncode == 0 and not unit.exists(), removed
            assert credential.read_bytes() == b'existing-secret\n'

        assert run(units, executable, '0.0.0.0', credential, 8081).returncode == 0
        original = unit.read_bytes()
        for altered in (
                original.replace(b'RestartSec=2s', b'RestartSec=3s'),
                original.replace(b'--port 8081', b'--port 08081'),
                original.replace(b'--port 8081', b'--port 65536'),
                original.replace(b'--host 0.0.0.0', b'--host localhost --log'),
                original + b'\n[Service]\nExecStart=/bin/sh\n',
                b'unrelated unit\n', b'x' * 7000):
            unit.write_bytes(altered)
            for action in ('inspect', 'remove-installed'):
                result = run(action, units)
                assert result.returncode != 0, result
                assert unit.read_bytes() == altered
        unit.write_bytes(original)
        unit.chmod(0o666)
        assert run('inspect', units).returncode != 0
        unit.chmod(0o644)
        linked = root / 'linked-unit'
        os.link(unit, linked)
        assert run('inspect', units).returncode != 0
        linked.unlink()
        unit.unlink()
        unit.symlink_to(credential)
        assert run('inspect', units).returncode != 0
        assert credential.read_bytes() == b'existing-secret\n'
        print('sandbox installed configuration discovery and collision safeguards: passed')


def verify_unit_replacement(driver):
    with tempfile.TemporaryDirectory(prefix='mergerfs-unit-replace-test-') as directory:
        root = Path(directory)
        units = root / 'units'
        units.mkdir(mode=0o700)
        unit = units / 'mergerfs-webui.service'
        credentials = root / 'credentials'

        def run(*arguments):
            return subprocess.run(arguments, capture_output=True, text=True, check=False)

        def write(executable='/usr/local/bin/mergerfs-webui', host='127.0.0.1',
                  password='/etc/mergerfs-webui/password', port='default'):
            return run(str(driver), str(units), executable, host, password, port)

        assert write().stdout.strip() == 'created', write()
        original = unit.read_bytes()
        original_inode = unit.stat().st_ino

        # Identical replacement is refused before touching the unit.
        same = run(str(driver), 'replace', str(units),
                   '/usr/local/bin/mergerfs-webui', '127.0.0.1',
                   '/etc/mergerfs-webui/password', 'default',
                   '/usr/local/bin/mergerfs-webui', '127.0.0.1',
                   '/etc/mergerfs-webui/password', 'default-port')
        assert same.returncode != 0 and unit.read_bytes() == original, same
        assert unit.stat().st_ino == original_inode

        # A mismatched current unit is refused; the file stays untouched.
        mismatched = run(str(driver), 'replace', str(units),
                         '/usr/local/bin/mergerfs-webui', '0.0.0.0',
                         '/etc/mergerfs-webui/password', 'default',
                         '/usr/local/bin/mergerfs-webui', '127.0.0.1',
                         'none', 'default-port')
        assert mismatched.returncode != 0 and unit.read_bytes() == original, mismatched
        assert unit.stat().st_ino == original_inode

        # Changing host and dropping the password replaces the unit atomically.
        updated = run(str(driver), 'replace', str(units),
                      '/usr/local/bin/mergerfs-webui', '127.0.0.1',
                      '/etc/mergerfs-webui/password', 'default',
                      '/usr/local/bin/mergerfs-webui', '0.0.0.0',
                      'none', 'default-port')
        assert updated.returncode == 0 and updated.stdout.strip() == 'replaced', updated
        text = unit.read_text()
        assert ('ExecStart=/usr/local/bin/mergerfs-webui --host 0.0.0.0'
                ' --port 8080\n') in text
        assert '--password-file' not in text
        assert unit.stat().st_mode & 0o777 == 0o644
        assert unit.stat().st_nlink == 1

        # The old unit content no longer matches; removal refuses it.
        stale = run(str(driver), 'remove', str(units),
                    '/usr/local/bin/mergerfs-webui', '127.0.0.1',
                    '/etc/mergerfs-webui/password', 'default')
        assert stale.returncode != 0 and unit.exists(), stale
        current = run(str(driver), 'inspect', str(units))
        assert current.returncode == 0 and current.stdout.strip() == (
            '/usr/local/bin/mergerfs-webui\t0.0.0.0\t8080'), current

        # Unsafe new hosts and injection attempts are rejected before writing.
        for arguments in (
                ['/usr/local/bin/mergerfs-webui', '127.0.0.1', 'none', 'default-port'],
                ['/usr/local/bin/mergerfs-webui', 'bad host', 'none', 'default-port'],
                ['/tmp/injected\n[Service]', '127.0.0.1', 'none', 'default-port']):
            before = unit.read_bytes()
            rejected = run(str(driver), 'replace', str(units),
                           '/usr/local/bin/mergerfs-webui', '0.0.0.0',
                           'none', 'default-port', *arguments)
            assert rejected.returncode != 0 and unit.read_bytes() == before, rejected

        # Only an existing managed password can be replaced.
        absent = run(str(driver), 'replace-password', str(credentials), 'secret')
        assert absent.returncode != 0 and not (credentials / 'password').exists(), absent
        run(str(driver), 'password', str(credentials), 'old-secret')
        managed = credentials / 'password'
        assert managed.read_bytes() == b'old-secret\n'
        replaced = run(str(driver), 'replace-password', str(credentials), 'new-secret')
        assert replaced.returncode == 0, replaced
        assert managed.read_bytes() == b'new-secret\n'
        assert managed.stat().st_mode & 0o7777 == 0o600
        for invalid in ('', 'A' * 129, 'has space', 'control\n'):
            before = managed.read_bytes()
            denied = run(str(driver), 'replace-password', str(credentials), invalid)
            assert denied.returncode != 0 and managed.read_bytes() == before, denied
        print('sandbox in-place unit and credential replacement: passed')


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
        runnable = subprocess.run([str(source), 'runnable-running'],
                                  capture_output=True, text=True, check=False)
        assert runnable.returncode == 0 and runnable.stdout.strip() == str(source), runnable
        if os.geteuid() == 0:
            # Reusing an existing credential is independent of atomic managed
            # destination ownership policies.
            current = root / 'current-password'
            current.write_bytes(b'existing-secret\n')
            current.chmod(0o666)
            nobody = pwd.getpwnam('nobody')
            os.chown(current, nobody.pw_uid, nobody.pw_gid)
            os.chown(source, nobody.pw_uid, nobody.pw_gid)
            success('validate', source, current, expected='valid')
            success('validate', source, 'none', expected='valid')

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
        for valid in ('!', '~' * 128, 'punctuation-_$%\\\"'):
            success('password', credentials, valid)
            assert password.read_bytes() == valid.encode() + b'\n'
        for invalid in ('', 'A' * 129, 'has space', 'control\n', 'é'):
            before = password.read_bytes()
            denied('password', credentials, invalid)
            assert password.read_bytes() == before
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
        print('sandbox executable and credential destination safeguards: passed')


if __name__ == '__main__':
    binary = Path(sys.argv[1] if len(sys.argv) > 1 else 'build/mergerfs-webui').resolve()
    driver = Path(sys.argv[2] if len(sys.argv) > 2 else 'build/test-service-install').resolve()
    verify(binary)
    verify_unit_inspection(driver)
    verify_unit_writer(driver)
    verify_unit_replacement(driver)
    verify_unit_removal(driver)
    verify_install_files(driver)
