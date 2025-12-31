#!/usr/bin/env python3
"""Exercise the piped installer without network access or privileged writes."""

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


INSTALLER = Path(__file__).resolve().parent.parent / 'install.sh'
REPO = 'trapexit/mergerfs-webui'
ASSET = 'mergerfs-webui_x86_64-linux-musl'
URL = f'https://github.com/{REPO}/releases/download/v1.2.3/{ASSET}'

# Only the network and host identity are isolated. Hashing, staging, installation,
# atomic replacement, and execution use the real Linux tools and executables.
SHIM = '''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import shutil
import sys

root = Path(os.environ['INSTALLER_FIXTURE'])
name = Path(sys.argv[0]).name
if name == 'uname':
    print(os.environ.get('FIXTURE_OS', 'Linux') if sys.argv[1] == '-s'
          else os.environ.get('FIXTURE_MACHINE', 'x86_64'))
elif name == 'getconf':
    print(os.environ.get('FIXTURE_BITS', '64'))
elif name == 'id':
    print('1000')
elif name == 'sudo':
    args = sys.argv[1:]
    if args[0] == '--':
        args.pop(0)
    with (root / 'sudo.log').open('a') as log:
        log.write(json.dumps(args) + '\\n')
    os.execvp(args[0], args)
elif name == 'curl':
    args = sys.argv[1:]
    url = args[args.index('--url') + 1]
    output = args[args.index('--output') + 1]
    api = 'https://api.github.com/repos/trapexit/mergerfs-webui/releases/latest'
    if url == api:
        if os.environ.get('FIXTURE_FAILURE') == 'metadata':
            sys.exit(22)
        source = root / 'release.json'
    else:
        release = json.loads((root / 'release.json').read_text())
        expected = ('https://github.com/trapexit/mergerfs-webui/releases/download/'
                    + release['tag_name'] + '/' + release['assets'][0]['name'])
        if url != expected:
            sys.exit(22)
        source = root / 'payload'
        if os.environ.get('FIXTURE_FAILURE') == 'download':
            Path(output).write_bytes(source.read_bytes()[:100])
            sys.exit(18)
    shutil.copyfile(source, output)
elif name == 'install':
    if os.environ.get('FIXTURE_FAILURE') == 'install':
        Path(sys.argv[-1]).write_bytes(b'partial installation')
        sys.exit(1)
    os.execv(os.environ['REAL_INSTALL'], ['install', *sys.argv[1:]])
'''


class Scenario:
    def __init__(self, root):
        self.root = root
        self.bin = root / 'bin'
        self.bin.mkdir()
        self.tmp = root / 'tmp'
        self.tmp.mkdir()
        self.destination = root / 'destination'
        self.destination.mkdir()
        self.executable = self.destination / 'mergerfs-webui'
        shutil.copyfile(shutil.which('sleep'), self.executable)
        self.executable.chmod(0o755)
        self.original = self.executable.read_bytes()
        self.payload = Path(shutil.which('true')).read_bytes()
        (root / 'payload').write_bytes(self.payload)
        self.metadata = {
            'tag_name': 'v1.2.3', 'draft': False, 'prerelease': False,
            'assets': [{'name': ASSET, 'state': 'uploaded', 'size': len(self.payload),
                        'browser_download_url': URL,
                        'digest': 'sha256:' + hashlib.sha256(self.payload).hexdigest()}],
        }
        shim = self.bin / 'shim'
        shim.write_text(SHIM)
        shim.chmod(0o755)
        for name in ('curl', 'uname', 'getconf', 'id', 'sudo', 'install'):
            (self.bin / name).symlink_to(shim)
        self.env = {
            **os.environ, 'PATH': str(self.bin) + os.pathsep + os.environ['PATH'],
            'INSTALLER_FIXTURE': str(root), 'INSTALL_DIR': str(self.destination),
            'TMPDIR': str(self.tmp), 'REAL_INSTALL': shutil.which('install'),
        }

    def run(self):
        (self.root / 'release.json').write_text(json.dumps(self.metadata))
        result = subprocess.run(['sh'], input=INSTALLER.read_bytes(), env=self.env,
                                capture_output=True, timeout=15)
        assert not list(self.tmp.iterdir()), 'download directory leaked'
        assert not list(self.destination.glob('.mergerfs-webui.*')), 'staging file leaked'
        return result

    def unchanged(self):
        assert self.executable.read_bytes() == self.original
        assert not (self.root / 'sudo.log').exists(), 'failure escalated privileges'


def verify():
    with tempfile.TemporaryDirectory(prefix='mergerfs-installer-test-') as directory:
        root = Path(directory)

        def scenario(name):
            folder = root / name
            folder.mkdir()
            return Scenario(folder)

        case = scenario('replace-running')
        running = subprocess.Popen([str(case.executable), '30'])
        try:
            result = case.run()
            assert result.returncode == 0, result.stderr.decode()
            assert case.executable.read_bytes() == case.payload
            assert case.executable.stat().st_mode & 0o777 == 0o755
            assert running.poll() is None, 'old process was stopped'
            subprocess.run([str(case.executable)], check=True, timeout=5)
            assert not (case.root / 'sudo.log').exists(), 'writable destination used sudo'
        finally:
            running.terminate()
            running.wait(timeout=5)

        case = scenario('corrupt-download')
        (case.root / 'payload').write_bytes(b'corrupt executable')
        result = case.run()
        assert result.returncode != 0 and b'SHA-256 verification failed' in result.stderr
        case.unchanged()

        for failure in ('metadata', 'download', 'install'):
            case = scenario(failure + '-failure')
            case.env['FIXTURE_FAILURE'] = failure
            assert case.run().returncode != 0
            case.unchanged()

        for name, change in (
            ('missing-digest', lambda release: release['assets'][0].pop('digest')),
            ('untrusted-url', lambda release: release['assets'][0].update(
                browser_download_url='https://example.com/executable')),
            ('prerelease', lambda release: release.update(prerelease=True)),
            ('unsafe-tag', lambda release: release.update(tag_name='../other')),
        ):
            case = scenario(name)
            change(case.metadata)
            assert case.run().returncode != 0
            case.unchanged()

        for name, settings in (
            ('unsupported-os', {'FIXTURE_OS': 'Darwin'}),
            ('unsupported-cpu', {'FIXTURE_MACHINE': 'i686', 'FIXTURE_BITS': '32'}),
            ('32-bit-userspace', {'FIXTURE_BITS': '32'}),
            ('relative-path', {'INSTALL_DIR': 'relative/path'}),
        ):
            case = scenario(name)
            case.env.update(settings)
            assert case.run().returncode != 0
            case.unchanged()

    print('installer checksum, failure isolation, and running-executable replacement: passed')


if __name__ == '__main__':
    verify()
