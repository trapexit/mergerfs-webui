#!/usr/bin/env python3
"""Exercise verified static archives and ownership decisions inside disposable roots."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import tarfile
import tempfile
import urllib.request


DIRS = ['usr/', 'usr/local/', 'usr/local/bin/', 'usr/local/lib/',
        'usr/local/lib/mergerfs/', 'usr/local/share/', 'usr/local/share/man/',
        'usr/local/share/man/man1/', 'sbin/']
FILES = {
    'usr/local/bin/mergerfs': 0o755,
    'usr/local/bin/mergerfs-fusermount': 0o4755,
    'usr/local/lib/mergerfs/preload.so': 0o444,
    'usr/local/share/man/man1/mergerfs.1': 0o644,
    'sbin/mount.mergerfs': 0o755,
}
ALIASES = ('usr/local/bin/fsck.mergerfs',
           'usr/local/bin/mergerfs.collect-info')


def invoke(driver, operation, root, owners=None, *arguments, switch=None):
    command = [str(driver), operation, str(root), '/usr/local/bin:/usr/bin',
               json.dumps(owners or {}), *map(str, arguments)]
    if switch is not None:
        command.append(switch)
    return json.loads(subprocess.check_output(command, text=True, timeout=60))


def sandbox(directory):
    root = directory / 'root'
    (root / 'usr' / 'bin').mkdir(parents=True)
    (root / 'sbin').mkdir()
    return root


def archive_file(where, executable, duplicate=False, bad_main_link=False):
    archive = where / 'release.tar.gz'
    binary = executable.read_bytes()
    with tarfile.open(archive, 'w:gz') as stream:
        for name in DIRS:
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            stream.addfile(info)
        for name, mode in FILES.items():
            info = tarfile.TarInfo(name)
            info.mode = mode
            if name == 'usr/local/bin/mergerfs' and bad_main_link:
                info.type = tarfile.SYMTYPE
                info.linkname = '../../etc/shadow'
                stream.addfile(info)
            else:
                data = b'mergerfs manual\n' if name.endswith('.1') else binary
                info.size = len(data)
                stream.addfile(info, io.BytesIO(data))
                if duplicate and name == 'usr/local/bin/mergerfs':
                    stream.addfile(info, io.BytesIO(data))
        for name in ALIASES:
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.mode = 0o777
            info.linkname = 'mergerfs'
            stream.addfile(info)
    return archive


def release_args(archive, digest=None):
    return (archive, '2.42.0', digest or hashlib.sha256(archive.read_bytes()).hexdigest(),
            archive.stat().st_size)


def offline(driver, executable):
    executable = executable.resolve()
    with tempfile.TemporaryDirectory(prefix='mergerfs-archive-test-') as directory:
        directory = Path(directory)
        archive = archive_file(directory, executable)
        binary = executable.read_bytes()

        root = sandbox(directory / 'missing')
        status = invoke(driver, 'status', root)['status']
        assert status['state'] == 'missing' and status['static_install_allowed'], status
        result = invoke(driver, 'install', root, {}, *release_args(archive), 'static')
        assert result['rc'] == 0, result
        for name, mode in FILES.items():
            destination = root / ('usr/local/sbin/mount.mergerfs' if name.startswith('sbin/') else name)
            assert destination.is_file() and destination.stat().st_mode & 0o7777 == mode, destination
            assert destination.read_bytes() == (b'mergerfs manual\n' if name.endswith('.1') else binary)
        assert (root / 'sbin/mount.mergerfs').read_bytes() == binary
        for alias in ALIASES:
            assert (root / alias).is_symlink() and os.readlink(root / alias) == 'mergerfs'

        root = sandbox(directory / 'manual-alias')
        manual = root / 'usr/local/man'
        manual.mkdir(parents=True)
        shared = root / 'usr/local/share'
        shared.mkdir()
        (shared / 'man').symlink_to('../man')
        result = invoke(driver, 'install', root, {}, *release_args(archive), 'static')
        assert result['rc'] == 0, result
        assert (shared / 'man').is_symlink() and os.readlink(shared / 'man') == '../man'
        assert (manual / 'man1/mergerfs.1').read_bytes() == b'mergerfs manual\n'
        assert (shared / 'man/man1/mergerfs.1').read_bytes() == b'mergerfs manual\n'
        assert (root / 'sbin/mount.mergerfs').read_bytes() == binary

        root = sandbox(directory / 'unsafe-manual-alias')
        shared = root / 'usr/local/share'
        shared.mkdir(parents=True)
        (shared / 'man').symlink_to('../../../../tmp')
        result = invoke(driver, 'install', root, {}, *release_args(archive), 'static')
        assert result['rc'] != 0 and not (root / 'usr/local/bin').exists(), result
        assert (shared / 'man').is_symlink()

        root = sandbox(directory / 'unmanaged')
        installed = root / 'usr/bin/mergerfs'
        installed.write_bytes(b'old mergerfs')
        installed.chmod(0o755)
        status = invoke(driver, 'status', root)['status']
        assert status['state'] == 'unmanaged' and status['in_place_allowed'], status
        result = invoke(driver, 'install', root, {}, *release_args(archive), 'existing')
        assert result['rc'] == 0 and result['result']['path'] == '/usr/bin/mergerfs', result
        assert installed.read_bytes() == binary
        assert not (root / 'usr/local').exists() and not (root / 'sbin/mount.mergerfs').exists()

        root = sandbox(directory / 'managed')
        installed = root / 'usr/bin/mergerfs'
        helper = root / 'sbin/mount.mergerfs'
        installed.write_bytes(b'packaged-main')
        installed.chmod(0o755)
        helper.write_bytes(b'packaged-helper')
        helper.chmod(0o755)
        owners = {'/usr/bin/mergerfs': 'package', '/sbin/mount.mergerfs': 'package'}
        status = invoke(driver, 'status', root, owners)['status']
        assert status['state'] == 'package' and not status['in_place_allowed'] and status['static_install_allowed'], status
        result = invoke(driver, 'install', root, owners, *release_args(archive), 'existing')
        assert result['rc'] != 0 and installed.read_bytes() == b'packaged-main', result
        result = invoke(driver, 'install', root, owners, *release_args(archive), 'static')
        assert result['rc'] == 0 and any('Preserved /sbin' in w for w in result['result']['warnings']), result
        assert installed.read_bytes() == b'packaged-main' and helper.read_bytes() == b'packaged-helper'
        assert (root / 'usr/local/bin/mergerfs').read_bytes() == binary
        assert (root / 'usr/local/sbin/mount.mergerfs').read_bytes() == binary

        root = sandbox(directory / 'blocked-helper')
        blocked = root / 'usr/local/bin/mergerfs-fusermount'
        blocked.parent.mkdir(parents=True)
        blocked.write_bytes(b'packaged local helper')
        blocked.chmod(0o755)
        result = invoke(driver, 'install', root,
                        {'/usr/local/bin/mergerfs-fusermount': 'package'},
                        *release_args(archive), 'static')
        assert result['rc'] != 0 and blocked.read_bytes() == b'packaged local helper', result
        assert not (root / 'usr/local/bin/mergerfs').exists()

        root = sandbox(directory / 'usr-merged')
        (root / 'sbin').rmdir()
        (root / 'usr/sbin').mkdir()
        (root / 'sbin').symlink_to('usr/sbin')
        result = invoke(driver, 'install', root, {}, *release_args(archive), 'static')
        assert result['rc'] == 0 and (root / 'usr/sbin/mount.mergerfs').read_bytes() == binary, result

        root = sandbox(directory / 'unknown')
        installed = root / 'usr/bin/mergerfs'
        installed.write_bytes(b'old')
        installed.chmod(0o755)
        result = invoke(driver, 'install', root, {'/usr/bin/mergerfs': 'unknown'},
                        *release_args(archive), 'existing')
        assert result['rc'] != 0 and installed.read_bytes() == b'old', result
        result = invoke(driver, 'install', root, {}, *release_args(archive), 'existing',
                        switch='/usr/bin/mergerfs')
        assert result['rc'] == -11 and installed.read_bytes() == b'old', result
        result = invoke(driver, 'install', root, {}, *release_args(archive, '0' * 64), 'static')
        assert result['rc'] != 0 and not (root / 'usr/local').exists(), result
        for name, options in (('duplicate', {'duplicate': True}),
                              ('symlink', {'bad_main_link': True})):
            bad = directory / name
            bad.mkdir()
            malicious = archive_file(bad, executable, **options)
            result = invoke(driver, 'install', root, {}, *release_args(malicious), 'static')
            assert result['rc'] != 0 and not (root / 'usr/local').exists(), result
        root = sandbox(directory / 'rollback')
        preload = root / 'usr/local/lib/mergerfs/preload.so'
        preload.parent.mkdir(parents=True)
        preload.write_bytes(b'original preload')
        preload.chmod(0o444)
        result = invoke(driver, 'install', root, {}, *release_args(archive), 'static',
                        switch='/usr/local/lib/mergerfs/preload.so@2')
        assert result['rc'] == -11 and preload.read_bytes() == b'original preload', result
        assert not (root / 'usr/local/bin').exists()
        assert not (root / 'usr/local/share').exists()
        assert not list(root.rglob('.mergerfs-*')), result
    print('isolated ownership and static archive installer: passed')


def live(driver):
    architecture = {'x86_64': 'amd64', 'aarch64': 'arm64',
                    'armv7l': 'armhf', 'riscv64': 'riscv64'}[platform.machine()]
    request = urllib.request.Request(
        'https://api.github.com/repos/trapexit/mergerfs/releases/latest',
        headers={'User-Agent': 'mergerfs-webui-live-smoke'})
    with urllib.request.urlopen(request, timeout=60) as response:
        metadata = json.load(response)
    tag = metadata['tag_name']
    name = f'mergerfs-{tag}-static-linux_{architecture}.tar.gz'
    assets = [asset for asset in metadata['assets'] if asset['name'] == name]
    assert len(assets) == 1 and assets[0]['digest'].startswith('sha256:')
    asset = assets[0]
    with tempfile.TemporaryDirectory(prefix='mergerfs-live-', dir='build') as directory:
        directory = Path(directory).resolve()
        root = sandbox(directory)
        manual = root / 'usr/local/man'
        manual.mkdir(parents=True)
        shared = root / 'usr/local/share'
        shared.mkdir()
        (shared / 'man').symlink_to('../man')
        archive = directory / name
        with urllib.request.urlopen(asset['browser_download_url'], timeout=90) as response:
            archive.write_bytes(response.read(64 * 1024 * 1024 + 1))
        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        assert digest == asset['digest'][7:] and archive.stat().st_size == asset['size']
        result = invoke(driver, 'install', root, {}, archive, tag, digest, asset['size'], 'static')
        assert result['rc'] == 0, result
        assert (shared / 'man').is_symlink()
        assert (manual / 'man1/mergerfs.1').is_file()
        version = subprocess.check_output([str(root / 'usr/local/bin/mergerfs'), '--version'],
                                          text=True, timeout=5).splitlines()[0]
        assert version == f'mergerfs v{tag}', version
        print('verified upstream static release sandbox --version:', version)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--live', action='store_true')
    parser.add_argument('driver', type=Path)
    parser.add_argument('executable', nargs='?', type=Path, default=Path('build/mergerfs-webui'))
    args = parser.parse_args()
    driver = args.driver.resolve()
    if args.live:
        live(driver)
    else:
        offline(driver, args.executable)
