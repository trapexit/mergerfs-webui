#!/bin/sh
# Install the latest stable GitHub release; never start or restart a service.

fail()
{
    printf 'mergerfs-webui installer: %s\n' "$*" >&2
    exit 1
}

as_root()
{
    if [ "$needs_sudo" -eq 1 ]; then
        sudo -- "$@"
    else
        command "$@"
    fi
}

cleanup()
{
    if [ -n "$staged_file" ]; then
        as_root rm -f -- "$staged_file" || :
    fi
    rm -rf -- "$tmp_dir"
}

main()
{
    set -eu
    [ "$#" -eq 0 ] || fail 'This installer takes no arguments; use INSTALL_DIR to change the destination.'

    for tool in uname getconf curl jq sha256sum mktemp id mkdir install mv rm; do
        command -v "$tool" >/dev/null 2>&1 || fail "Required command not found: $tool"
    done
    [ "$(uname -s)" = Linux ] || fail 'Only Linux is supported.'
    machine=$(uname -m)
    bits=$(getconf LONG_BIT)
    case "$machine:$bits" in
        x86_64:64) target=x86_64-linux-musl ;;
        aarch64:64|arm64:64) target=aarch64-linux-musl ;;
        armv7l:32|armv8l:32) target=arm-linux-musleabihf ;;
        riscv64:64) target=riscv64-linux-musl ;;
        *) fail "Unsupported architecture: $machine ($bits-bit userspace)" ;;
    esac
    asset=mergerfs-webui_$target
    install_dir=${INSTALL_DIR:-/usr/local/bin}
    case "$install_dir" in
        /*) ;;
        *) fail 'INSTALL_DIR must be an absolute path.' ;;
    esac

    needs_sudo=0
    if [ "$(id -u)" -ne 0 ] && { [ ! -d "$install_dir" ] || [ ! -w "$install_dir" ]; }; then
        command -v sudo >/dev/null 2>&1 || fail "Installing into $install_dir requires root or sudo. Alternatively, set INSTALL_DIR to an existing writable directory."
        needs_sudo=1
    fi

    tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/mergerfs-webui.XXXXXX")
    staged_file=
    trap cleanup 0
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM

    repo=trapexit/mergerfs-webui
    printf 'Finding the latest stable release for %s...\n' "$machine"
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --output "$tmp_dir/release.json" \
        --url "https://api.github.com/repos/$repo/releases/latest" \
        || fail 'Could not fetch the latest stable release from GitHub.'

    # Pin both the download and checksum to one release. Never parse JSON with grep.
    jq --exit-status --raw-output --arg asset "$asset" \
        --arg base "https://github.com/$repo/releases/download" '
        select(.draft == false and .prerelease == false)
        | (.tag_name | select(test("^[A-Za-z0-9][A-Za-z0-9._-]*$"))) as $tag
        | [.assets[] | select(.name == $asset)]
        | select(length == 1) | .[0]
        | select(.state == "uploaded" and .size > 0)
        | ($base + "/" + $tag + "/" + $asset) as $url
        | select(.browser_download_url == $url)
        | (.digest | select(test("^sha256:[0-9a-f]{64}$"))) as $digest
        | $url, ($digest | ltrimstr("sha256:"))
        ' "$tmp_dir/release.json" > "$tmp_dir/selected" \
        || fail "Latest release has no valid $asset asset with a SHA-256 digest."
    {
        IFS= read -r asset_url
        IFS= read -r digest
    } < "$tmp_dir/selected"

    printf 'Downloading %s...\n' "$asset"
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --output "$tmp_dir/$asset" --url "$asset_url" \
        || fail "Could not download $asset."
    printf '%s  %s\n' "$digest" "$tmp_dir/$asset" | sha256sum --check --status \
        || fail 'SHA-256 verification failed; the existing installation was not changed.'

    # Stage on the destination filesystem so replacing a running binary is atomic.
    as_root mkdir -p -- "$install_dir"
    staged_file=$(as_root mktemp "$install_dir/.mergerfs-webui.XXXXXX")
    as_root install -m 0755 -- "$tmp_dir/$asset" "$staged_file"
    as_root mv -fT -- "$staged_file" "$install_dir/mergerfs-webui"
    staged_file=
    printf 'Installed %s/mergerfs-webui (%s).\n' "$install_dir" "$asset"
    printf 'No service was started or restarted. Restart an existing server to use the new executable.\n'
}

# Defining main before calling it prevents a truncated curl stream from installing.
main "$@"
