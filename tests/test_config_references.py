#!/usr/bin/env python3
"""Exercise startup config-reference edits against the HTTP server."""

import json
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

PASSWORD = 'test-persistence-password'


def request(base, method, route, payload=None, authenticated=True):
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {'Content-Type': 'application/json'}
    if authenticated:
        headers['Authorization'] = 'Bearer ' + PASSWORD
    req = urllib.request.Request(base + route, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=2) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


def sources(base, mount):
    status, result = request(base, 'GET', '/persistence?mount=' + urllib.parse.quote(str(mount)))
    assert status == 200, (status, result)
    return {source['path'] for source in result['sources']}


def edit(base, mount, kind, source, key, value, expected=200):
    status, result = request(base, 'POST', '/persistence?mount=' + urllib.parse.quote(str(mount)),
                             {'source': {'type': kind, 'path': str(source)}, 'key': key,
                              'value': str(value)})
    assert status == expected, (status, result)


def verify_mount_action_rejections(base, root, fstab_mount, systemd_mount, unit):
    # Only request paths that must reject before invoking mount, umount, or systemctl.
    fstab = root / 'fstab'
    fstab_mount.mkdir(parents=True, exist_ok=True)
    systemd_mount.mkdir(exist_ok=True)
    before = (fstab.read_bytes(), unit.read_bytes())
    selected = {'type': 'fstab', 'path': str(fstab)}
    action = {'action': 'mount', 'mountpoint': str(fstab_mount), 'source': selected}

    status, result = request(base, 'POST', '/mount-actions', action, authenticated=False)
    assert status == 401 and 'error' in result, (status, result)

    for payload, expected, message in (
        ({**action, 'action': 'start'}, 422, 'unknown mount action'),
        ({**action, 'mountpoint': str(fstab_mount / '..' / 'fstab')},
         422, 'canonical path'),
        ({**action, 'source': {'type': 'ini', 'path': str(fstab)}},
         422, 'fstab or systemd source'),
        ({**action, 'source': {'type': 'fstab', 'path': str(root / 'not-fstab')}},
         404, 'not configured'),
        ({'action': 'mount', 'mountpoint': str(systemd_mount),
          'source': {'type': 'systemd', 'path': str(root / 'units/not-selected.mount')}},
         404, 'not configured'),
        ({'action': 'umount', 'mountpoint': str(fstab_mount)},
         404, 'not a running mergerfs mount'),
    ):
        status, result = request(base, 'POST', '/mount-actions', payload)
        assert status == expected and message in result['error']['msg'], (
            payload, status, result)

    assert (fstab.read_bytes(), unit.read_bytes()) == before


def verify(base, root):
    fstab = root / 'fstab'
    alpha, beta, gamma = (root / 'configs' / (name + '.ini') for name in ('alpha', 'beta', 'gamma'))
    for file in (alpha, beta, gamma):
        file.write_text('fsname=' + file.stem + '\n')
    fstab_mount = root / 'pool/fstab'
    status, result = request(base, 'GET', '/mount-definitions', authenticated=False)
    assert status == 401, (status, result)
    status, result = request(base, 'POST', '/mount-definitions',
                             {'type': 'fstab', 'mountpoint': str(root / 'pool/unauthorized'),
                              'branches': str(root / 'disk/unauthorized') + '=RW',
                              'options': {}, 'ini_path': ''}, authenticated=False)
    assert status == 401 and not fstab.read_text(), (status, result)
    systemd_mount = root / 'pool/systemd'
    for kind, mount in (('fstab', fstab_mount), ('systemd', systemd_mount)):
        status, result = request(base, 'POST', '/mount-definitions',
                                 {'type': kind, 'mountpoint': str(mount),
                                  'branches': str(root / 'disk' / kind) + '=RW',
                                  'options': {'fsname': kind}, 'ini_path': ''})
        assert status == 201, (status, result)
        if kind == 'systemd':
            unit = Path(result['path'])
            assert f'What={root / "disk" / kind}\n' in unit.read_text()
        else:
            assert f'{root / "disk" / kind}\t{mount}\t' in fstab.read_text()

    verify_mount_action_rejections(base, root, fstab_mount, systemd_mount, unit)

    edit(base, fstab_mount, 'fstab', fstab, 'config', alpha)
    assert sources(base, fstab_mount) == {str(fstab), str(alpha)}
    edit(base, fstab_mount, 'fstab', fstab, 'config', beta)
    assert 'config=' + str(beta) in fstab.read_text()
    assert sources(base, fstab_mount) == {str(fstab), str(beta)}
    edit(base, fstab_mount, 'ini', beta, 'config', gamma)
    assert sources(base, fstab_mount) == {str(fstab), str(beta), str(gamma)}
    edit(base, fstab_mount, 'ini', gamma, 'fsname', 'updated')
    assert gamma.read_text() == 'fsname=updated\n'

    edit(base, fstab_mount, 'ini', gamma, 'config', beta, 422)
    edit(base, fstab_mount, 'ini', beta, 'config', beta, 422)
    edit(base, fstab_mount, 'fstab', fstab, 'config', root / 'missing.ini', 404)
    link = root / 'configs/link.ini'
    link.symlink_to(alpha)
    edit(base, fstab_mount, 'fstab', fstab, 'config', link, 422)
    assert 'config=' + str(beta) in fstab.read_text()
    assert beta.read_text() == 'fsname=beta\nconfig=' + str(gamma) + '\n'
    assert gamma.read_text() == 'fsname=updated\n'

    edit(base, systemd_mount, 'systemd', unit, 'config', alpha)
    assert 'config=' + str(alpha) in unit.read_text()
    edit(base, systemd_mount, 'systemd', unit, 'config', gamma)
    assert sources(base, systemd_mount) == {str(unit), str(gamma)}

    service_mount = root / 'pool/service'
    target = root / 'configs/service.ini'
    wrapper = root / 'configs/wrapper.ini'
    next_wrapper = root / 'configs/next.ini'
    target.write_text('mountpoint=' + str(service_mount) + '\nbranches=' + str(root / 'disk/service') + '\n')
    wrapper.write_text('config=' + str(target) + '\n')
    next_wrapper.write_text('config=' + str(target) + '\n')
    service = root / 'units/mergerfs-nested.service'
    service.write_text('[Service]\nExecStart=/usr/bin/mergerfs -f -o config=' + str(wrapper) + '\n')
    assert sources(base, service_mount) == {str(service), str(wrapper), str(target)}
    status, listed = request(base, 'GET', '/mount-definitions')
    assert status == 200, (status, listed)
    assert str(service_mount) in listed['mounts'], listed
    edit(base, service_mount, 'systemd', service, 'config', next_wrapper)
    assert sources(base, service_mount) == {str(service), str(next_wrapper), str(target)}
    edit(base, service_mount, 'systemd', service, 'config', gamma, 422)
    assert 'config=' + str(next_wrapper) in service.read_text()


def verify_mount_unit_names():
    # A temporary root cannot exercise /.pool through the HTTP creation API.
    # Call the filename encoder directly to cover systemd's leading-dot rule.
    source = r'''
#include "src/persistence.cpp"
int main()
{
  return ((Persistence::mount_unit_name("/.pool") == "\\x2epool.mount") &&
          (Persistence::mount_unit_name("/pool/.hidden") == "pool-.hidden.mount") &&
          (Persistence::mount_unit_name("/pool/with-dash") == "pool-with\\x2ddash.mount"))
    ? 0 : 1;
}
'''
    with tempfile.TemporaryDirectory(prefix='mergerfs-unit-name-test-') as directory:
        driver = Path(directory) / 'unit-names'
        subprocess.run(['c++', '-std=c++17', '-ffunction-sections', '-fdata-sections',
                        '-Wl,--gc-sections', '-x', 'c++', '-', '-o', str(driver)],
                       input=source, text=True, check=True,
                       cwd=Path(__file__).resolve().parent.parent)
        subprocess.run([str(driver)], check=True)


def serve(binary, root, args, check, host='127.0.0.1'):
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1', 0))
        port = reserved.getsockname()[1]
    base = f'http://127.0.0.1:{port}'
    server = subprocess.Popen([str(binary.resolve()), '--host', host, '--port', str(port),
                               '--fstab', str(root / 'fstab'), '--systemd-dir', str(root / 'units'),
                               *args], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 10
        while True:
            if server.poll() is not None:
                raise AssertionError('webui server exited before readiness')
            try:
                request(base, 'GET', '/mounts', authenticated=False)
                break
            except urllib.error.URLError:
                if time.monotonic() >= deadline:
                    raise AssertionError('webui server did not become ready')
                time.sleep(0.05)
        check(base)
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()


def main(binary):
    verify_mount_unit_names()
    with tempfile.TemporaryDirectory(prefix='mergerfs-config-test-') as directory:
        root = Path(directory)
        (root / 'fstab').touch()
        (root / 'units').mkdir()
        (root / 'configs').mkdir()
        (root / 'password').write_text(PASSWORD + '\n')

        def open_access(base):
            status, result = request(base, 'GET', '/mount-definitions/capabilities',
                                     authenticated=False)
            assert status == 200 and result['enabled'] is True, (status, result)
            mount = root / 'pool/unrestricted'
            status, result = request(base, 'POST', '/mount-definitions',
                                     {'type': 'fstab', 'mountpoint': str(mount),
                                      'branches': str(root / 'disk/unrestricted') + '=RW',
                                      'options': {}, 'ini_path': ''}, authenticated=False)
            assert status == 201 and result['mountpoint'] == str(mount), (status, result)
            status, result = request(base, 'GET', '/mount-definitions', authenticated=False)
            assert status == 200 and str(mount) in result['mounts'], (status, result)
            status, result = request(base, 'POST',
                                     '/persistence?mount=' + urllib.parse.quote(str(mount)),
                                     {'source': {'type': 'fstab', 'path': str(root / 'fstab')},
                                      'key': 'fsname', 'value': 'public'}, authenticated=False)
            assert status == 200 and 'fsname=public' in (root / 'fstab').read_text(), (status, result)

        serve(binary, root, [], open_access, host='0.0.0.0')
        (root / 'fstab').write_text('')
        serve(binary, root, ['--password-file', str(root / 'password')],
              lambda base: verify(base, root), host='0.0.0.0')
        print('config-reference integration: passed')


if __name__ == '__main__':
    main(Path(sys.argv[1] if len(sys.argv) > 1 else 'build/mergerfs-webui'))
