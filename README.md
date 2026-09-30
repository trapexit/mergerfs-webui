# mergerfs-webui

mergerfs-webui is a browser-based tool for viewing and managing
[mergerfs](https://github.com/trapexit/mergerfs) mounts on Linux. The
server is a single executable with the web server and web page built
in.

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


## Download and install

The installer selects the latest stable Linux release for x86-64,
AArch64, ARMv7/ARMv8 32-bit hard-float, or RISC-V 64-bit:

```sh
curl -fsSL https://raw.githubusercontent.com/trapexit/mergerfs-webui/HEAD/install.sh | sh
```

It requires `curl`, `jq`, and standard Linux utilities (including
`getconf`, `sha256sum`, and GNU-compatible `install` and `mv`). It
checks the executable against GitHub's release-asset SHA-256 digest
before installing to `/usr/local/bin/mergerfs-webui`. Downloads and
verification run as your current user; only installation uses `sudo`
when needed. An existing running executable can be replaced, but no
service is started or restarted automatically.

Alternatively, download a static binary for your platform from the
[releases](https://github.com/trapexit/mergerfs-webui/releases) and
install it manually:

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

The default listener is `127.0.0.1:8080`: only processes on the server
can connect directly. Choose an access path appropriate for your
users:

### One administrator: SSH tunnel

On a headless server, leave the web UI running with its default
loopback bind.  From your own computer, run:

```sh
ssh -L 8080:127.0.0.1:8080 user@server
```

Open http://127.0.0.1:8080/ in your computer's browser. SSH encrypts
the connection between your computer and the server; no browser is
needed on the server. Without an application password, local users on
either computer and SSH users allowed to forward ports to the server
can use the web UI. Restrict those accounts or configure
`--password-file` as well. Press Ctrl+C in the server terminal to stop
a manually started instance.

### Multiple clients: HTTPS reverse proxy

Keep the web UI bound to `127.0.0.1` behind a trusted TLS reverse
proxy on the **same server**, and start it with a root-owned, private
password file:

```sh
sudo /usr/local/bin/mergerfs-webui --password-file /etc/mergerfs-webui/password
```

Create the file before starting the web UI. It must contain a nonempty
password on one line. A strong password and private, root-owned storage
are recommended (for example, file mode `0600` and directory mode
`0700`). Do not put the password in a shell command
argument. Terminate HTTPS at the proxy, restrict who can reach it, and
preserve the browser's `Host` and `Origin` headers so same-origin
write checks continue to work. HTTP between a local proxy and the
loopback listener does not traverse the network; a proxy on another
machine needs an encrypted upstream tunnel. The web UI does **not**
provide TLS itself.

### Trusted VPN

Alternatively, bind to the server's **VPN interface address**, not to
every interface, and enable password protection:

```sh
sudo /usr/local/bin/mergerfs-webui --host <VPN-IP> --password-file /etc/mergerfs-webui/password
```

The VPN encrypts transport and limits network access; the application
password still controls who can change mounts and startup
settings. Every VPN peer can reach the login endpoint: restrict VPN
membership and use a strong password.

`--host 0.0.0.0` explicitly listens on every IPv4 interface, not just
a VPN interface. Without authentication, anyone who can reach the
listener can use its write endpoints. Direct plain
HTTP on a LAN or the Internet also exposes passwords to network
observers; a firewall does not encrypt credentials. Use SSH, TLS, or a
VPN instead.

Running as root allows the application to manage system mount
configuration and set up its systemd service. For automatic startup,
open **Setup**, choose the service options, then select **Set up and
start service**:

- **Listener:** localhost (`127.0.0.1`), all IPv4 interfaces
  (`0.0.0.0`), or a custom host/IP address.
- **Port:** any TCP port from `1` to `65535`.
- **Executable:** copy the running version to
  `/usr/local/bin/mergerfs-webui` (default), or use the currently running
  executable without copying it.
- **Authentication:** no password, reuse the current server's password
  file, or use a new password. New passwords accept `1`–`128` printable
  ASCII characters without spaces or controls; setup generates a
  32-character default that you can edit.

These choices are independent of the foreground server's configuration.
All-interface access without a password and executable paths writable
by non-root users are allowed; security warnings explain the risks but
do not restrict those choices. Requests to the foreground server still
require its configured password. Setup requires root, systemd, valid
inputs, and safe installation destinations; it will not overwrite an
unrelated unit.

Save a new password before closing the tab. It is written during setup,
even if starting the service later fails, and is not displayed on later
visits. Starting an already installed service reuses its password file
without regenerating it.

Installed listener, port, and authentication options can be changed in
place: adjust them in Setup and select **Apply changes and restart
service**. The unit file is replaced atomically, systemd reloads it, and
the service restarts with the new settings; when this web UI is running
as that service, it briefly disconnects and systemd restarts it. A new
password rotates the managed password file. The executable and its
installation mode remain fixed; remove the unit and set it up again to
change them.

The foreground server exits after handing over to the service. If the
listener or port changes, setup shows the destination to open. Localhost
means the **server's** computer, not a remote browser's computer; remote
setup of a localhost service shows SSH-tunnel instructions instead of a
misleading local link. Existing units keep their configured listener
after an upgrade; an explicit `--host 0.0.0.0` remains network-facing
until the unit is changed.

The web UI's updater replaces the executable at its current location,
including after the running file or its directory has been renamed.
After an update, restart the application to run the installed release.
If the executable has been deleted without a replacement, restore it
at the reported path before checking for updates or restarting.


## Build from source

Run `make` for a native debug build (`-O0 -ggdb -ftrapv`) at
`build/mergerfs-webui`. Run `make NDEBUG=1` for a smaller native
binary (`-Os`, LTO, function/data sections, static linking, disabled
RTTI, section garbage collection, and stripped symbols). `make release`
uses Zig and `-Oz` for static cross-platform Linux binaries; run
`make zig-venv` first if Zig is not installed.

Versions use the UTC build-start timestamp `YYYYMMDDHHMMSS`, for
example `20260930130943`. There is no daily counter to maintain.
The timestamp is selected once per `make` invocation and shared with
recursive builds, so every architecture produced by `make release`
has the same version. Builds started in the same second can share a
version; timestamps are not a guarantee of unique build identity.

A normal build selects a fresh timestamp, even for unchanged sources.
To retain a published version across rebuilds, supply it explicitly:

```sh
make NDEBUG=1 VERSION=20260930130943
make VERSION=20260930130943 release
```

Use the matching release tag, for example `v20260930130943`, when
publishing those binaries.

`tools/release-to-github` automates this. Commit everything first; it refuses
to run with uncommitted build inputs. It builds all four binaries with
one UTC timestamp, verifies the untouched source commit, pushes the
annotated tag, and uploads a GitHub draft release:

```sh
tools/release-to-github [--publish]
```

Review the draft's generated notes, then publish it as latest. Use
`--publish` to do both in one run. Supply `VERSION` to retry a failed
run without generating another timestamp. Existing local or remote tags
are never overwritten.


## Support

https://trapexit.github.io/mergerfs/latest/support/


## Sponsorship and Donations

[https://github.com/trapexit/support](https://github.com/trapexit/support)

Development and support of a project like mergerfs and this webui
requires a significant amount of time and effort. The software is
released under the very liberal
[ISC](https://opensource.org/license/isc-license-txt) license and is
therefore free to use for personal or commercial uses.

If you are a non-commercial user and find mergerfs and its support
valuable and would like to support the project financially it would be
very much appreciated.

If you are using mergerfs commercially please consider sponsoring the
project to ensure it continues to be maintained and receive
updates. If custom features are needed feel free to [contact me
directly](mailto:support@spawn.link).
