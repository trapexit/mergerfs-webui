#!/usr/bin/env python3
"""Exercise the served login UI in headless Chromium against an isolated server."""

from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

try:
    from playwright.sync_api import expect, sync_playwright
except ModuleNotFoundError as error:
    if error.name == 'playwright':
        raise SystemExit('Playwright is required: see README.md (make test-browser)') from error
    raise


PASSWORD = 'browser-test-secret'


def verify_login(base, version):
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True)
        try:
            page = browser.new_page()
            with page.expect_response(lambda response: response.url.endswith('/auth')) as auth:
                page.goto(base + '/', wait_until='domcontentloaded')
            assert auth.value.json()['password_required'] is True
            # The response can arrive before the page's async initAuth finishes.
            page.wait_for_function('AppState.passwordRequired === true')
            expect(page.locator('#app-version')).to_have_text(version)
            password = page.locator('#password-input')
            verify = page.locator('#auth-btn')
            restart = page.locator('#restart-server-btn')

            # This instance requires a password, and a protected action is
            # unavailable before verification.
            expect(password).to_be_enabled()
            expect(verify).to_have_text('Verify')
            expect(restart).to_be_disabled()

            password.fill('not-the-password')
            with page.expect_response(lambda response: response.url.endswith('/auth/verify')) as result:
                verify.click()
            assert result.value.status == 401, 'wrong password was accepted by the server'
            expect(verify).to_have_text('Failed')
            expect(verify).to_be_enabled()
            expect(password).to_be_enabled()
            expect(password).to_have_value('')
            expect(restart).to_be_disabled()

            password.fill(PASSWORD)
            with page.expect_response(lambda response: response.url.endswith('/auth/verify')) as result:
                verify.click()
            assert result.value.status == 200, 'correct password was rejected by the server'
            expect(verify).to_have_text('Verified')
            expect(verify).to_be_disabled()
            expect(password).to_be_disabled()
            expect(restart).to_be_enabled()  # Do not click: it restarts the server.
        finally:
            browser.close()


def main(binary):
    page_path = Path(__file__).resolve().parent.parent / 'webui/index.html'
    with tempfile.TemporaryDirectory(prefix='mergerfs-browser-auth-') as directory:
        root = Path(directory)
        (root / 'fstab').touch()
        (root / 'units').mkdir()
        password_file = root / 'password'
        password_file.write_text(PASSWORD + '\n')
        password_file.chmod(0o600)
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            port = reserved.getsockname()[1]
        base = f'http://127.0.0.1:{port}'
        server = subprocess.Popen(
            [str(binary.resolve()), '--host', '127.0.0.1', '--port', str(port),
             '--fstab', str(root / 'fstab'), '--systemd-dir', str(root / 'units'),
             '--password-file', str(password_file), '--index.html', str(page_path)],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 10
            while True:
                if server.poll() is not None:
                    raise AssertionError('webui server exited before readiness')
                try:
                    with urllib.request.urlopen(base + '/auth', timeout=2) as response:
                        assert response.status == 200
                    break
                except urllib.error.URLError:
                    if time.monotonic() >= deadline:
                        raise AssertionError('webui server did not become ready')
                    time.sleep(0.05)
            reported = subprocess.check_output([str(binary.resolve()), '--version'],
                                               text=True, timeout=5).strip()
            assert reported.startswith('mergerfs-webui v'), reported
            version = reported[len('mergerfs-webui '):]
            verify_login(base, version)
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()
    print('browser authentication integration: passed')


if __name__ == '__main__':
    main(Path(sys.argv[1] if len(sys.argv) > 1 else 'build/mergerfs-webui'))
