#!/usr/bin/env python3
"""Exercise persistence previews and revision-guarded saves over HTTP."""

import json
import os
import stat
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


def request(base, method, route, payload=None, auth=True, extra_headers=None):
    body = json.dumps(payload).encode() if payload is not None else None
    headers = {'Content-Type': 'application/json'}
    if auth:
        headers['Authorization'] = 'Bearer ' + PASSWORD
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(base + route, data=body, method=method,
                                 headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=2) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


def edit(base, mount, kind, source, key, value, preview=False, revision=None,
         remove=False):
    route = '/persistence/preview' if preview else '/persistence'
    route += '?mount=' + urllib.parse.quote(str(mount))
    payload = {'source': {'type': kind, 'path': str(source)},
               'key': key, 'value': str(value)}
    if remove:
        payload['remove'] = True
    if revision is not None:
        payload['expected_revision'] = revision
    return request(base, 'POST', route, payload)


def expect(base, mount, kind, source, key, value, preview=False, revision=None,
           status=200, remove=False):
    actual, result = edit(base, mount, kind, source, key, value, preview,
                          revision, remove)
    assert actual == status, (actual, result)
    return result


def snapshot(path):
    stat = path.stat()
    return path.read_bytes(), stat.st_ino, stat.st_mtime_ns


def raw_route(mount, kind=None, source=None):
    route = '/persistence/raw?mount=' + urllib.parse.quote(str(mount))
    if kind is not None:
        route += '&type=' + urllib.parse.quote(kind)
    if source is not None:
        route += '&path=' + urllib.parse.quote(str(source))
    return route


def raw_read(base, mount, kind, source, status=200):
    actual, result = request(base, 'GET', raw_route(mount, kind, source))
    assert actual == status, (actual, result)
    return result


def raw_save(base, mount, kind, source, text, revision, status=200):
    actual, result = request(base, 'POST', raw_route(mount),
                             {'source': {'type': kind, 'path': str(source)},
                              'text': text, 'expected_revision': revision})
    assert actual == status, (actual, result)
    return result


def preserved_metadata(path):
    result = [stat.S_IMODE(path.stat().st_mode)]
    try:
        result.append(os.getxattr(path, 'user.mergerfs_raw_test'))
    except OSError:
        pass
    return result


def set_metadata(path):
    path.chmod(0o640)
    try:
        os.setxattr(path, 'user.mergerfs_raw_test', b'keep')
    except OSError:
        pass
    return preserved_metadata(path)


def verify_raw(base, root):
    fstab = root / 'fstab'
    mount = root / 'pool/raw'
    branch = root / 'disk/raw'
    unrelated = (b'# unrelated-secret-never-expose\r\n'
                 b'/dev/sdb /unrelated ext4 defaults 0 0\n')
    entry = f'{branch}=RW\t{mount}\tfuse.mergerfs\tfsname=old\t0\t0'
    fstab.write_bytes(unrelated + entry.encode() + b'\r\n# another unrelated-secret\n')
    mode = set_metadata(fstab)
    route = raw_route(mount, 'fstab', fstab)
    actual, _ = request(base, 'GET', route, auth=False)
    assert actual == 401, actual
    actual, _ = request(base, 'POST', raw_route(mount), {}, auth=False)
    assert actual == 401, actual
    actual, _ = request(base, 'POST', raw_route(mount), {'source': {}})
    assert actual == 400, actual
    actual, _ = request(base, 'POST', raw_route(mount),
                        {'source': {'type': 'fstab', 'path': str(fstab)},
                         'text': entry, 'expected_revision': ''})
    assert actual == 400, actual
    old = raw_read(base, mount, 'fstab', fstab)
    assert old == {'type': 'fstab', 'path': str(fstab), 'text': entry,
                   'revision': old['revision'], 'scope': 'entry'}, old
    assert old['revision'], old
    for secret in ('unrelated-secret-never-expose', 'another unrelated-secret', '/dev/sdb'):
        assert secret not in json.dumps(old), old
    updated = entry.replace('fsname=old', 'fsname=changed')
    for bad in ('', updated + '\n' + entry, updated + '\r', updated + '\x00',
                updated + '\x01',
                updated.replace(str(mount), str(root / 'wrong')),
                updated.replace('fuse.mergerfs', 'ext4'),
                updated.replace(f'{branch}=RW', 'relative=RW')):
        raw_save(base, mount, 'fstab', fstab, bad, old['revision'], status=422)
    assert fstab.read_bytes() == unrelated + entry.encode() + b'\r\n# another unrelated-secret\n'
    assert raw_save(base, mount, 'fstab', fstab, updated, old['revision'])['result'] == 'success'
    assert fstab.read_bytes() == unrelated + updated.encode() + b'\r\n# another unrelated-secret\n'
    assert preserved_metadata(fstab) == mode
    unchanged = snapshot(fstab)
    raw_save(base, mount, 'fstab', fstab, updated, old['revision'], status=409)
    assert snapshot(fstab) == unchanged
    newest = raw_read(base, mount, 'fstab', fstab)
    raw_save(base, mount, 'fstab', fstab, updated, newest['revision'])
    assert snapshot(fstab) == unchanged, 'raw no-op replaced fstab'
    fstab.write_bytes(unrelated + updated.encode())
    eof = raw_read(base, mount, 'fstab', fstab)
    raw_save(base, mount, 'fstab', fstab, entry, eof['revision'])
    assert fstab.read_bytes() == unrelated + entry.encode(), 'raw save added a final newline'
    stale = raw_read(base, mount, 'fstab', fstab)
    fstab.write_bytes(b'# concurrently changed\n' + entry.encode())
    concurrent = snapshot(fstab)
    raw_save(base, mount, 'fstab', fstab, updated, stale['revision'], status=409)
    assert snapshot(fstab) == concurrent
    fstab.write_bytes(b'')

    unit = root / 'units/raw.mount'
    unit.write_text(f'[Mount]\nWhat={branch}=RW\nWhere={mount}\n'
                    'Type=fuse.mergerfs\nOptions=fsname=old\n')
    unit_mode = set_metadata(unit)
    selected = raw_read(base, mount, 'systemd', unit)
    assert selected['text'] == unit.read_text() and selected['scope'] == 'file'
    raw_save(base, mount, 'systemd', unit,
             selected['text'].replace('fsname=old', 'fsname=changed'),
             selected['revision'])
    assert 'fsname=changed' in unit.read_text()
    assert preserved_metadata(unit) == unit_mode
    selected = raw_read(base, mount, 'systemd', unit)
    raw_save(base, mount, 'systemd', unit, selected['text'] + '\x01',
             selected['revision'], status=422)
    raw_save(base, mount, 'systemd', unit, selected['text'] + '# new\n',
             'incorrect-revision', status=409)
    raw_read(base, mount, 'systemd', root / 'units/other.mount', status=404)
    linked = root / 'units/linked.mount'
    linked.symlink_to(unit)
    raw_read(base, mount, 'systemd', linked, status=404)
    linked.unlink()
    service = root / 'units/raw.service'
    service.write_text(f'[Service]\nExecStart=/usr/bin/mergerfs {branch}=RW {mount}\n')
    raw_read(base, mount, 'systemd', service, status=422)
    selected = raw_read(base, mount, 'systemd', unit)
    raw_save(base, mount, 'systemd', service, service.read_text(),
             selected['revision'], status=422)
    unit.unlink()
    service.unlink()

    ini = root / 'configs/raw.ini'
    ini.write_text('fsname=raw\n')
    mode = set_metadata(ini)
    fstab.write_text(f'{branch}=RW {mount} fuse.mergerfs config={ini} 0 0\n')
    selected = raw_read(base, mount, 'ini', ini)
    assert selected['text'] == 'fsname=raw\n' and selected['scope'] == 'file'
    raw_save(base, mount, 'ini', ini, 'fsname=changed\n', selected['revision'])
    assert ini.read_text() == 'fsname=changed\n'
    assert preserved_metadata(ini) == mode
    raw_read(base, mount, 'ini', root / 'configs/undiscovered.ini', status=404)
    raw_save(base, mount, 'ini', root / 'configs/undiscovered.ini',
             'fsname=never\n', selected['revision'], status=404)
    selected = raw_read(base, mount, 'ini', ini)
    raw_save(base, mount, 'ini', ini, 'fsname=\x00\n', selected['revision'], status=422)
    untouched = snapshot(ini)
    ini.unlink()
    ini.symlink_to(root / 'configs/elsewhere.ini')
    (root / 'configs/elsewhere.ini').write_text('fsname=elsewhere\n')
    raw_save(base, mount, 'ini', ini, 'fsname=wrong\n', selected['revision'], status=422)
    raw_read(base, mount, 'ini', ini, status=422)
    assert snapshot(root / 'configs/elsewhere.ini')[0] == b'fsname=elsewhere\n'
    ini.unlink()
    ini.write_bytes(untouched[0])
    fstab.write_bytes(b'')

def assert_preview(result, path, before, after, first_line):
    assert result['path'] == str(path), result
    assert result['changed'] is True, result
    assert result['before'] == before, result
    assert result['after'] == after, result
    assert result['before_line'] == result['after_line'] == first_line, result
    assert isinstance(result['revision'], str) and result['revision'], result


def verify_fstab(base, root):
    fstab = root / 'fstab'
    mount = root / 'pool/fstab'
    previous = root / 'disk/previous'
    next_branch = root / 'disk/next'
    unrelated = '# unrelated-secret-never-expose\n/dev/sda1 /unrelated ext4 defaults 0 0\n'
    old_line = (f'{previous}=RW {mount} fuse.mergerfs '
                f'fsname=old,x-systemd.requires-mounts-for={previous} 0 0\n')
    new_line = (f'{next_branch} {mount} fuse.mergerfs '
                f'fsname=old,x-systemd.requires-mounts-for={next_branch} 0 0\n')
    fstab.write_text(unrelated + old_line + '# another unrelated-secret\n')
    original = snapshot(fstab)
    result = expect(base, mount, 'fstab', fstab, 'branches', f'{next_branch}=RW',
                    preview=True)
    assert_preview(result, fstab, old_line, new_line, 3)
    assert result['config_before'] == [str(fstab)], result
    assert result['config_after'] == [str(fstab)], result
    for secret in ('unrelated-secret-never-expose', 'another unrelated-secret'):
        assert secret not in result['before'] and secret not in result['after'], result
    assert snapshot(fstab) == original, 'preview mutated fstab'

    expect(base, mount, 'fstab', fstab, 'branches', f'{next_branch}=RW',
           revision=result['revision'])
    assert fstab.read_text() == unrelated + new_line + '# another unrelated-secret\n'
    no_op_before = snapshot(fstab)
    no_op = expect(base, mount, 'fstab', fstab, 'branches', f'{next_branch}=RW',
                   preview=True)
    assert no_op['changed'] is False, no_op
    assert no_op['before'] == no_op['after'] == '', no_op
    assert no_op['before_line'] == no_op['after_line'] == 0, no_op
    assert no_op['config_before'] == no_op['config_after'] == [str(fstab)], no_op
    assert snapshot(fstab) == no_op_before, 'no-op preview mutated fstab'
    expect(base, mount, 'fstab', fstab, 'branches', f'{next_branch}=RW',
           revision=no_op['revision'])
    assert snapshot(fstab) == no_op_before, 'no-op save rewrote fstab'
    for invalid in ('relative=RW', f'{next_branch}=INVALID', f'{next_branch}=RW:'):
        expect(base, mount, 'fstab', fstab, 'branches', invalid,
               preview=True, status=422)
    expect(base, mount, 'fstab', fstab, 'branches', f'{next_branch}=INVALID', status=422)
    assert snapshot(fstab) == no_op_before, 'invalid branches modified fstab'


    edit_preview = expect(base, mount, 'fstab', fstab, 'fsname', 'updated', preview=True)
    concurrent_line = new_line.replace('fsname=old', 'fsname=other')
    fstab.write_text(unrelated + concurrent_line + '# another unrelated-secret\n')
    concurrent = snapshot(fstab)
    expect(base, mount, 'fstab', fstab, 'fsname', 'updated',
           revision=edit_preview['revision'], status=409)
    assert snapshot(fstab) == concurrent, 'stale revision overwrote fstab'
    fstab.write_text(unrelated + f'{previous}=RW {mount} fuse.mergerfs fsname=old 0 0\n')
    without_dependencies = snapshot(fstab)
    expect(base, mount, 'fstab', fstab, 'branches', 'relative=RW', status=422)
    assert snapshot(fstab) == without_dependencies, 'relative branch modified fstab'
    minimum = root / 'disk/minimum'
    no_create = root / 'disk/no-create'
    mixed = f'{previous}=RW:{next_branch}=RO:{no_create}=NC:{minimum}=RW,10G'
    mixed_line = (f'{previous}:{next_branch}=RO:{no_create}=NC:{minimum}=RW,10G '
                  f'{mount} fuse.mergerfs fsname=old 0 0\n')
    preview = expect(base, mount, 'fstab', fstab, 'branches', mixed, preview=True)
    assert preview['changed'] and mixed_line in preview['after'], preview
    expect(base, mount, 'fstab', fstab, 'branches', mixed, revision=preview['revision'])
    assert fstab.read_text() == unrelated + mixed_line
    # One systemd dependency per branch: an explicit single-value edit must
    # not change just the first dependency and strand the second one.
    first, second = previous, next_branch
    old_dependencies = (f'{first}:{second}=RO {mount} fuse.mergerfs '
                        f'fsname=old,x-systemd.requires-mounts-for={first},'
                        f'x-systemd.requires-mounts-for={second} 0 0\n')
    fstab.write_text(unrelated + old_dependencies)
    before = snapshot(fstab)
    expect(base, mount, 'fstab', fstab, 'x-systemd.requires-mounts-for',
           str(root / 'disk/different'), preview=True, status=422)
    assert snapshot(fstab) == before, 'ambiguous dependency preview modified fstab'
    expect(base, mount, 'fstab', fstab, 'x-systemd.requires-mounts-for',
           str(root / 'disk/different'), status=422)
    assert snapshot(fstab) == before, 'ambiguous dependency edit modified fstab'
    # A single branch can still have duplicate dependency options. The edit
    # must check the options themselves, not just the branch count.
    repeated_line = (f'{first}=RW {mount} fuse.mergerfs '
                     f'fsname=old,x-systemd.requires-mounts-for={first},'
                     f'x-systemd.requires-mounts-for={second} 0 0\n')
    fstab.write_text(unrelated + repeated_line)
    repeated_before = snapshot(fstab)
    for preview in (True, False):
        rejected = expect(base, mount, 'fstab', fstab,
                          'x-systemd.requires-mounts-for', str(first),
                          preview=preview, status=422)
        assert set(rejected) == {'error'} and set(rejected['error']) == {'msg'}, rejected
        assert snapshot(fstab) == repeated_before, 'rejected dependency edit modified fstab'

    # A single stale dependency can be rewritten to its configured branch.
    stale_line = (f'{first}=RW {mount} fuse.mergerfs '
                  f'fsname=old,x-systemd.requires-mounts-for={second} 0 0\n')
    corrected_line = (f'{first}=RW {mount} fuse.mergerfs '
                      f'fsname=old,x-systemd.requires-mounts-for={first} 0 0\n')
    fstab.write_text(unrelated + stale_line)
    stale_before = snapshot(fstab)
    corrected = expect(base, mount, 'fstab', fstab,
                       'x-systemd.requires-mounts-for', str(first), preview=True)
    assert_preview(corrected, fstab, stale_line, corrected_line, 3)
    assert snapshot(fstab) == stale_before, 'dependency preview modified fstab'
    saved = expect(base, mount, 'fstab', fstab,
                   'x-systemd.requires-mounts-for', str(first),
                   revision=corrected['revision'])
    assert saved['result'] == 'success', saved
    assert fstab.read_text() == unrelated + corrected_line

    fstab.write_text(unrelated + old_dependencies)
    before = snapshot(fstab)
    third = root / 'disk/third'
    fourth = root / 'disk/fourth'
    replacement = (f'{third}:{fourth}=RO {mount} fuse.mergerfs '
                   f'fsname=old,x-systemd.requires-mounts-for={third},'
                   f'x-systemd.requires-mounts-for={fourth} 0 0\n')
    result = expect(base, mount, 'fstab', fstab, 'branches',
                    f'{third}=RW:{fourth}=RO', preview=True)
    assert result['after'] == replacement, result
    assert snapshot(fstab) == before, 'dependency rewrite preview modified fstab'
    expect(base, mount, 'fstab', fstab, 'branches', f'{third}=RW:{fourth}=RO',
           revision=result['revision'])
    assert fstab.read_text() == unrelated + replacement
    expect(base, mount, 'fstab', fstab, 'fsname', 'updated')
    assert fstab.read_text() == unrelated + replacement.replace('fsname=old', 'fsname=updated')


def verify_systemd(base, root):
    mount = root / 'pool/systemd'
    unit = root / 'units/pool-systemd.mount'
    previous = root / 'disk/old-unit'
    next_branch = root / 'disk/new-unit'
    initial = ('[Unit]\nDescription=preview fixture\n'
               f'RequiresMountsFor={previous}\n\n[Mount]\n'
               f'What={previous}=RW\nWhere={mount}\nType=fuse.mergerfs\n'
               'Options=fsname=old\n\n[Install]\nWantedBy=multi-user.target\n')
    unit.write_text(initial)
    old_span = (f'RequiresMountsFor={previous}\n\n[Mount]\n'
                f'What={previous}=RW\n')
    new_span = (f'RequiresMountsFor={next_branch}\n\n[Mount]\n'
                f'What={next_branch}\n')
    initial_snapshot = snapshot(unit)
    result = expect(base, mount, 'systemd', unit, 'branches', f'{next_branch}=RW',
                    preview=True)
    assert_preview(result, unit, old_span, new_span, 3)
    assert result['config_before'] == result['config_after'] == [str(unit)], result
    assert snapshot(unit) == initial_snapshot, 'preview mutated systemd unit'
    expect(base, mount, 'systemd', unit, 'branches', f'{next_branch}=RW',
           revision=result['revision'])
    assert unit.read_text() == initial.replace(old_span, new_span)

    service_mount = root / 'pool/service-branches'
    service = root / 'units/branch-positional.service'
    initial_service = f'[Service]\nExecStart=/usr/bin/mergerfs -f {previous}=RW {service_mount}\n'
    service.write_text(initial_service)
    value = f'{next_branch}=RW:{previous}=RO'
    preview = expect(base, service_mount, 'systemd', service, 'branches', value, preview=True)
    assert preview['changed'] and f' -f {next_branch}:{previous}=RO {service_mount}' in preview['after'], preview
    expect(base, service_mount, 'systemd', service, 'branches', value,
           revision=preview['revision'])
    assert service.read_text() == initial_service.replace(
        f'{previous}=RW', f'{next_branch}:{previous}=RO')


def verify_ini_branches(base, root):
    mount = root / 'pool/ini-branches'
    previous = root / 'disk/ini-old'
    next_branch = root / 'disk/ini-new'
    config = root / 'configs/branch-default.ini'
    service = root / 'units/branch-default.service'
    original = f'mountpoint={mount}\nbranches={previous}=RW\nfsname=original\n'
    config.write_text(original)
    service.write_text(f'[Service]\nExecStart=/usr/bin/mergerfs -f -o config={config}\n')
    value = f'{next_branch}=RW:{previous}=RO'
    preview = expect(base, mount, 'ini', config, 'branches', value, preview=True)
    assert preview['changed'] and f'branches={next_branch}:{previous}=RO\n' in preview['after'], preview
    assert config.read_text() == original
    expect(base, mount, 'ini', config, 'branches', value, revision=preview['revision'])
    assert config.read_text() == f'mountpoint={mount}\nbranches={next_branch}:{previous}=RO\nfsname=original\n'


def verify_config_chain(base, root):
    fstab = root / 'fstab'
    mount = root / 'pool/configs'
    first, previous, next_config = (root / 'configs' / (name + '.ini')
                                    for name in ('first', 'previous', 'next'))
    first.write_text('fsname=first\nconfig=' + str(previous) + '\n')
    previous.write_text('fsname=previous\n')
    next_config.write_text('fsname=next\n')
    fstab.write_text(f'{root / "disk/configs"}=RW {mount} fuse.mergerfs '
                     f'config={first} 0 0\n')
    before_chain = [str(first), str(previous)]
    after_chain = [str(first), str(next_config)]
    old_line = f'config={previous}\n'
    new_line = f'config={next_config}\n'
    originals = {path: snapshot(path) for path in (fstab, first, previous, next_config)}
    result = expect(base, mount, 'ini', first, 'config', next_config, preview=True)
    assert_preview(result, first, old_line, new_line, 2)
    assert result['config_before'] == before_chain, result
    assert result['config_after'] == after_chain, result
    assert {path: snapshot(path) for path in originals} == originals, 'preview mutated config chain'
    expect(base, mount, 'ini', first, 'config', next_config,
           revision=result['revision'])
    assert first.read_text() == 'fsname=first\n' + new_line

    unchanged = snapshot(first)
    no_op = expect(base, mount, 'ini', first, 'config', next_config, preview=True)
    assert no_op['changed'] is False, no_op
    assert no_op['before'] == no_op['after'] == '', no_op
    assert no_op['config_before'] == no_op['config_after'] == after_chain, no_op
    assert snapshot(first) == unchanged

    chain_preview = expect(base, mount, 'ini', first, 'fsname', 'renamed', preview=True)
    next_config.write_text('fsname=concurrent\n')
    concurrent = snapshot(first)
    expect(base, mount, 'ini', first, 'fsname', 'renamed',
           revision=chain_preview['revision'], status=409)
    assert snapshot(first) == concurrent, 'changed config chain allowed stale save'

    link = root / 'configs/link.ini'
    link.symlink_to(previous)
    before = snapshot(first)
    expect(base, mount, 'ini', first, 'config', root / 'configs/missing.ini',
           preview=True, status=404)
    expect(base, mount, 'ini', first, 'config', link, preview=True, status=422)
    expect(base, mount, 'ini', first, 'config', first, preview=True, status=422)
    expect(base, mount, 'ini', root / 'configs/unreferenced.ini', 'fsname', 'new',
           preview=True, status=404)
    assert snapshot(first) == before, 'rejected preview mutated ini file'


def verify_option_removal(base, root):
    fstab = root / 'fstab'
    mount = root / 'pool/remove'
    branch = root / 'disk/remove'
    prefix = '# unrelated\n'
    entry = f'{branch}=RW {mount} fuse.mergerfs fsname=old,cache.files=partial 0 0\r\n'
    fstab.write_bytes(prefix.encode() + entry.encode())
    initial = snapshot(fstab)
    route = '/persistence/preview?mount=' + urllib.parse.quote(str(mount))
    body = {'source': {'type': 'fstab', 'path': str(fstab)},
            'key': 'cache.files', 'value': '', 'remove': True}
    for changes in ({'remove': 'true'}, {'value': 'partial'}):
        status, result = request(base, 'POST', route, {**body, **changes})
        assert status == 400, (changes, status, result)
    assert snapshot(fstab) == initial
    preview = expect(base, mount, 'fstab', fstab, 'cache.files', '',
                     preview=True, remove=True)
    assert_preview(preview, fstab, entry,
                   entry.replace('fsname=old,cache.files=partial', 'fsname=old'), 2)
    assert snapshot(fstab) == initial
    fstab.write_bytes(prefix.encode() + entry.replace('fsname=old', 'fsname=new').encode())
    changed = snapshot(fstab)
    expect(base, mount, 'fstab', fstab, 'cache.files', '',
           revision=preview['revision'], status=409, remove=True)
    assert snapshot(fstab) == changed
    preview = expect(base, mount, 'fstab', fstab, 'cache.files', '',
                     preview=True, remove=True)
    expect(base, mount, 'fstab', fstab, 'cache.files', '',
           revision=preview['revision'], remove=True)
    assert fstab.read_bytes() == (prefix + entry.replace(
        'fsname=old,cache.files=partial', 'fsname=new')).encode()
    expect(base, mount, 'fstab', fstab, 'cache.files', '',
           preview=True, status=404, remove=True)
    for key in ('branches', 'mountpoint', 'version', 'cmd.gc'):
        expect(base, mount, 'fstab', fstab, key, '', preview=True,
               status=422, remove=True)
    preview = expect(base, mount, 'fstab', fstab, 'fsname', '',
                     preview=True, remove=True)
    expect(base, mount, 'fstab', fstab, 'fsname', '',
           revision=preview['revision'], remove=True)
    assert fstab.read_text().splitlines()[1] == (
        f'{branch}=RW {mount} fuse.mergerfs defaults 0 0')

    unit = root / 'units/remove.mount'
    unit.write_bytes((f'[Mount]\r\nWhat={branch}=RW\r\nWhere={mount}\r\n'
                      'Type=fuse.mergerfs\r\nOptions=fsname=old\r\n'
                      '\r\n[Install]\r\nWantedBy=multi-user.target\r\n').encode())
    preview = expect(base, mount, 'systemd', unit, 'fsname', '',
                     preview=True, remove=True)
    expect(base, mount, 'systemd', unit, 'fsname', '',
           revision=preview['revision'], remove=True)
    assert b'Options=' not in unit.read_bytes()
    assert b'\r\n[Install]\r\n' in unit.read_bytes()

    service = root / 'units/remove.service'
    service.write_text(f'[Service]\nExecStart=/usr/bin/mergerfs -o fsname=old '
                       f'{branch}=RW {mount}\n')
    preview = expect(base, mount, 'systemd', service, 'fsname', '',
                     preview=True, remove=True)
    expect(base, mount, 'systemd', service, 'fsname', '',
           revision=preview['revision'], remove=True)
    assert service.read_text() == (
        f'[Service]\nExecStart=/usr/bin/mergerfs {branch}=RW {mount}\n')

    first = root / 'configs/remove.ini'
    second = root / 'configs/remove-next.ini'
    second.write_text('fsname=second\n')
    first.write_bytes((f'fsname=first\r\nconfig={second}\r\n# keep\r\n').encode())
    fstab.write_text(f'{branch}=RW {mount} fuse.mergerfs config={first} 0 0\n')
    expect(base, mount, 'fstab', fstab, 'fsname', '',
           preview=True, status=404, remove=True)
    previous = snapshot(first)
    preview = expect(base, mount, 'ini', first, 'config', '',
                     preview=True, remove=True)
    assert preview['config_before'] == [str(first), str(second)]
    assert preview['config_after'] == [str(first)]
    assert snapshot(first) == previous
    expect(base, mount, 'ini', first, 'config', '',
           revision=preview['revision'], remove=True)
    assert first.read_bytes() == b'fsname=first\r\n# keep\r\n'
    expect(base, mount, 'ini', first, 'config', '',
           preview=True, status=404, remove=True)


def verify_write_protection(base, mount, fstab):
    route = '/persistence?mount=' + urllib.parse.quote(str(mount))
    payload = {'source': {'type': 'fstab', 'path': str(fstab)},
               'key': 'fsname', 'value': 'cross-origin'}
    before = snapshot(fstab)
    for headers, expected in (
        ({'Origin': 'http://evil.example', 'Sec-Fetch-Site': 'cross-site',
          'Content-Type': 'text/plain'}, 403),
        ({'Origin': 'http://evil.example'}, 403),
        ({'Origin': 'null'}, 403),
        ({'Origin': base + '.evil.example'}, 403),
        ({'Origin': base + '/path'}, 403),
        ({'Origin': base, 'Sec-Fetch-Site': 'same-site'}, 403),
        ({'Sec-Fetch-Site': 'cross-site'}, 403),
        ({'Origin': 'https://evil.example',
          'X-Forwarded-Host': 'evil.example', 'X-Forwarded-Proto': 'https'}, 403),
        ({'Origin': base, 'Content-Type': 'text/plain'}, 415),
        ({'Content-Type': 'application/x-www-form-urlencoded'}, 415),
        ({'Content-Type': 'multipart/form-data; boundary=test'}, 415),
        ({'Content-Type': ''}, 415),
    ):
        status, result = request(base, 'POST', route, payload, auth=False,
                                 extra_headers=headers)
        assert status == expected, (headers, status, result)
        assert snapshot(fstab) == before, 'rejected browser request changed fstab'

    # Origin protection also applies to DELETE and commands with no request body.
    status, result = request(base, 'DELETE', '/mount-definitions',
                             {'mountpoint': str(mount),
                              'source': payload['source'], 'confirmation': str(mount)},
                             auth=False, extra_headers={'Origin': 'http://evil.example'})
    assert status == 403, (status, result)
    assert snapshot(fstab) == before
    status, result = request(base, 'POST', '/auth/verify', auth=False,
                             extra_headers={'Origin': 'http://evil.example'})
    assert status == 403, (status, result)

    # Keep direct browser access, non-browser clients, and Host-preserving TLS
    # proxies working; forwarded headers do not establish a trusted origin.
    for index, headers in enumerate((
        {'Origin': base, 'Sec-Fetch-Site': 'same-origin'},
        {},
        {'Origin': base, 'Content-Type': 'Application/JSON; charset=utf-8'},
        {'Origin': 'https://storage.example', 'Host': 'storage.example'},
        {'Origin': 'http://storage.example', 'Host': 'storage.example:80'},
        {'Origin': 'https://storage.example', 'Host': 'storage.example:443'},
        {'Origin': 'http://[::1]:8080', 'Host': '[::1]:8080'},
    )):
        payload['value'] = f'allowed-{index}'
        status, result = request(base, 'POST', route, payload, auth=False,
                                 extra_headers=headers)
        assert status == 200, (headers, status, result)
        assert f'fsname=allowed-{index}' in fstab.read_text()


def verify_raw_local_only(binary, root):
    fstab = root / 'fstab'
    mount = root / 'pool/local-only'
    entry = f'{root / "disk/local"}=RW {mount} fuse.mergerfs fsname=old 0 0'
    fstab.write_text(entry + '\n')
    with socket.socket() as reserved:
        reserved.bind(('127.0.0.1', 0))
        port = reserved.getsockname()[1]
    base = f'http://127.0.0.1:{port}'
    server = subprocess.Popen([str(binary.resolve()), '--host', '127.0.0.1',
                               '--port', str(port), '--fstab', str(fstab),
                               '--systemd-dir', str(root / 'units')],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 10
        while True:
            if server.poll() is not None:
                raise AssertionError('passwordless webui server exited before readiness')
            try:
                request(base, 'GET', '/mounts', auth=False)
                break
            except urllib.error.URLError:
                if time.monotonic() >= deadline:
                    raise AssertionError('passwordless webui server did not become ready')
                time.sleep(0.05)
        route = raw_route(mount, 'fstab', fstab)
        actual, denied = request(base, 'GET', route, auth=False,
                                 extra_headers={'Forwarded': 'for=192.0.2.1'})
        assert actual == 403, (actual, denied)
        actual, current = request(base, 'GET', route, auth=False)
        assert actual == 200 and current['text'] == entry, (actual, current)
        payload = {'source': {'type': 'fstab', 'path': str(fstab)},
                   'text': entry.replace('fsname=old', 'fsname=local'),
                   'expected_revision': current['revision']}
        actual, denied = request(base, 'POST', raw_route(mount), payload, auth=False,
                                 extra_headers={'Forwarded': 'for=192.0.2.1'})
        assert actual == 403, (actual, denied)
        actual, result = request(base, 'POST', raw_route(mount), payload, auth=False)
        assert actual == 200 and result['result'] == 'success', (actual, result)
        assert 'fsname=local' in fstab.read_text()
        verify_write_protection(base, mount, fstab)
    finally:
        server.terminate()
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
            server.wait()


def main(binary):
    with tempfile.TemporaryDirectory(prefix='mergerfs-preview-test-') as directory:
        root = Path(directory)
        (root / 'fstab').touch()
        (root / 'units').mkdir()
        (root / 'configs').mkdir()
        (root / 'password').write_text(PASSWORD + '\n')
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1', 0))
            port = reserved.getsockname()[1]
        base = f'http://127.0.0.1:{port}'
        server = subprocess.Popen([str(binary.resolve()), '--host', '127.0.0.1',
                                   '--port', str(port), '--password-file', str(root / 'password'),
                                   '--fstab', str(root / 'fstab'), '--systemd-dir', str(root / 'units')],
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 10
            while True:
                if server.poll() is not None:
                    raise AssertionError('webui server exited before readiness')
                try:
                    request(base, 'GET', '/mounts')
                    break
                except urllib.error.URLError:
                    if time.monotonic() >= deadline:
                        raise AssertionError('webui server did not become ready')
                    time.sleep(0.05)
            verify_raw(base, root)
            verify_fstab(base, root)
            verify_systemd(base, root)
            verify_ini_branches(base, root)
            verify_config_chain(base, root)
            verify_option_removal(base, root)
            verify_raw_local_only(binary, root)
            print('persistence-preview integration: passed')
        finally:
            server.terminate()
            try:
                server.wait(timeout=5)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait()


if __name__ == '__main__':
    main(Path(sys.argv[1] if len(sys.argv) > 1 else 'build/mergerfs-webui'))
