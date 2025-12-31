# mergerfs-webui

mergerfs-webui is a browser-based tool for viewing and managing
[mergerfs](https://github.com/trapexit/mergerfs) mounts on Linux. The
server is a single executable with the web page built in.

The header displays the running server's version, matching `--version`.
Installing an update replaces the executable on disk; restart the server to
display the new version.

**NOTE:** This is a pre-1.0 release. UI and UX may not be
ideal. Please file a
[ticket](https://github.com/trapexit/mergerfs-webui/issues) with
suggestions.


## What it can do

- Install `mergerfs`.
- Update `mergerfs-webui`.
- Setup `mergerfs-webui` to run as a service via systemd.
- Create `mergerfs` mounts via `/etc/fstab` or a systemd `.mount`
  file.
- Mount and unmount `mergerfs` mounts.
- Discover running `mergerfs` mounts and inspect and modify their
  runtime settings.
- Add and remove branches and change `mergerfs` policies on a running
  mount.
- Edit startup configuration in `/etc/fstab`, systemd `.mount` units,
  and referenced `mergerfs` ini files. Preview structured changes
  before saving, or edit a discovered source as raw text.
- Issue runtime commands.

For fstab entries with `x-systemd.requires-mounts-for` dependencies, edit the
branches to update their dependency list. A direct single-value edit cannot
represent multiple branch dependencies and is rejected.

## Download and install

Download a static binary for your platform from the
[releases](https://github.com/trapexit/mergerfs-webui/releases).

```
$ sudo install -m 0755 mergerfs-webui_x86_64-linux-musl /usr/local/bin/mergerfs-webui

$ sudo /usr/local/bin/mergerfs-webui --help
Usage: mergerfs-webui [options]

A simple web UI to configure mergerfs instances

  --host <address>      Interface to bind to (default: 127.0.0.1)
  --port <1..65535>     TCP port to use (default: 8080)
  --password-file <path> Read password from file (one trailing newline removed)
  --fstab <path>        fstab path (default: /etc/fstab)
  --systemd-dir <path>  systemd unit directory (overrides defaults)
  --index.html <path>   Serve a local page for development
  --version             Show the application version
  --help                Show this help

sudo /usr/local/bin/mergerfs-webui
```

The default listener is `127.0.0.1:8080`: only processes on the server can
connect directly. Choose an access path appropriate for your users:

### One administrator: SSH tunnel

On a headless server, leave the web UI running with its default loopback bind.
From your own computer, run:

```sh
ssh -L 8080:127.0.0.1:8080 user@server
```

Open http://127.0.0.1:8080/ in your computer's browser. SSH encrypts the
connection between your computer and the server; no browser is needed on the
server. Without an application password, local users on either computer and
SSH users allowed to forward ports to the server can use the web UI. Restrict
those accounts or configure `--password-file` as well. Press Ctrl+C in the
server terminal to stop a manually started instance.

### Multiple clients: HTTPS reverse proxy

Keep the web UI bound to `127.0.0.1` behind a trusted TLS reverse proxy on
the **same server**, and start it with a root-owned, private password file:

```sh
sudo /usr/local/bin/mergerfs-webui --password-file /etc/mergerfs-webui/password
```

Create the file as root before starting the web UI. It must contain a strong,
nonempty password on one line; keep it and its parent directory private (for
example, file mode `0600` and directory mode `0700`). Do not put the password
in a shell command argument. Terminate HTTPS at the proxy, restrict who can
reach it, and preserve the browser's `Host` and `Origin` headers so same-origin
write checks continue to work. HTTP between a local proxy and the loopback
listener does not traverse the network; a proxy on another machine needs an
encrypted upstream tunnel. The web UI does **not** provide TLS itself.

### Trusted VPN

Alternatively, bind to the server's **VPN interface address**, not to every
interface, and enable password protection:

```sh
sudo /usr/local/bin/mergerfs-webui --host <VPN-IP> --password-file /etc/mergerfs-webui/password
```

The VPN encrypts transport and limits network access; the application password
still controls who can change mounts and startup settings. Every VPN peer can
reach the login endpoint: restrict VPN membership and use a strong password.

`--host 0.0.0.0` explicitly listens on every IPv4 interface, not just a VPN
interface. Do not expose it without authentication. Direct plain HTTP on a
LAN or the Internet also exposes passwords to network observers; a firewall
does not encrypt credentials. Use SSH, TLS, or a VPN instead.

Running as root allows the application to manage system mount
configuration and set up its systemd service. For automatic startup,
open **Setup** then choose **Set up and start service**. The service
uses the current host and port and, by default, installs the running
executable at `/usr/local/bin/mergerfs-webui`. If you choose **Require
password for this service**, save the generated password displayed
during setup; it will not be shown again. Setup replaces an existing
managed service password, so the old one stops working. This step
requires a systemd-based Linux installation. An existing unit with an
explicit `--host 0.0.0.0` remains network-facing after an upgrade: review
its `ExecStart` rather than assuming the new default changes that unit.


## Build from source

Run `make` for a native debug build (`-O0 -ggdb -ftrapv`) at
`build/mergerfs-webui`. Run `make NDEBUG=1` for a smaller native binary (`-Os`, LTO,
function/data sections, static linking, section garbage collection, and
stripped symbols). `make release` uses Zig and `-Oz` for static cross-platform
Linux binaries; run `make zig-venv` first if Zig is not installed.

Both native modes write the same path; run `make clean` before switching modes
so Make does not reuse the previous binary.

The Makefile discovers `src/*.cpp` and source/vendored headers with globs.
Each source builds to its own object; compiler-generated `.d` files track the
headers each object includes, including the generated page header. Objects
for different Zig targets are kept in separate directories. Run `make test`
for the existing test suite.

The browser login regression test is separate from `make test` because it
requires Python Playwright and a downloaded Chromium runtime. Install and run
it explicitly (the local `.venv/` is ignored by Git):

```sh
python3 -m venv .venv
.venv/bin/python -m pip install 'playwright==1.63.0'
.venv/bin/python -m playwright install chromium
make test-browser PYTHON=.venv/bin/python
```

`make test-browser` starts a disposable password-protected server on loopback
with temporary fstab and systemd-unit paths, serves `webui/index.html`, and
checks that a wrong password leaves the login editable and authenticated
actions disabled before a correct password verifies and enables them. It
fails if Playwright or its Chromium runtime is missing; it does not silently
skip. On systems lacking Chromium shared libraries, run
`.venv/bin/python -m playwright install-deps chromium` (may require root)
before retrying. The test does not perform privileged mount or service
actions.

`make clean` removes `build/`. `make distclean` also removes the project's
default `.venv/` (used by Zig and optionally browser tests); it does not
delete other untracked files.

Check first-party C++ formatting with:

```sh
te-format format --check --lang cpp --exclude src/favicon_ico.h src tests
```

Use `--write` instead of `--check` to format. Do not reformat vendored code
or the generated favicon header.

In new mount-command code, declare locals at the start of each block. Assign
runtime results immediately before they are needed, rather than mixing
declarations into later execution steps; retain initialization at declaration
when required by C++ construction, constness, or reference binding.

Build API response bodies with `nlohmann::json` and `.dump()`, not handwritten
serialized JSON strings. Python tests use `json.dumps` except when exercising
malformed input or duplicate object keys.

## Access and safety

**Do not expose an unauthenticated listener to a network.** The default bind
is now `127.0.0.1`, but an explicit `--host 0.0.0.0` or network address makes
the server reachable beyond loopback. Without `--password-file`, anyone who
can connect can change settings; even with a password, plain HTTP exposes it
to network observers. Use the SSH, local TLS-proxy, or trusted VPN setups
above as appropriate. Back up mount configuration before editing raw sources.

Startup configuration edits do not remount live filesystems; after
editing a systemd mount unit, run `systemctl daemon-reload` before
restarting the unit. Application updates require `/usr/bin/curl`,
`/usr/bin/sha256sum`, a compatible published release, and write access
to the executable directory.

Mount actions accept systemd unit names with a nonempty stem and a `.mount`
or `.service` suffix; before starting one, the server verifies that systemd
loaded the selected unit file.


## Support

https://trapexit.github.io/mergerfs/latest/support/


## Sponsorship and Donations

[https://github.com/trapexit/support](https://github.com/trapexit/support)

Development and support of a project like mergerfs and this webui
requires a significant amount of time and effort. The software is
released under the very liberal
[ISC](https://opensource.org/license/isc-license-txt) license and is
therefore free to use for personal or commercial uses.

If you are a non-commercial user and find mergerfs and its support valuable
and would like to support the project financially it would be very
much appreciated.

If you are using mergerfs commercially please consider sponsoring the
project to ensure it continues to be maintained and receive
updates. If custom features are needed feel free to [contact me
directly](mailto:support@spawn.link).
