#!/usr/bin/env python3
"""Package one built GKI payload as a KernelSU device-test ZIP.

Unlike package-module.py this needs no VM evidence and ships a single KMI.
It exists for payloads validated on a real device instead (for example the
Samsung EL2 kprobe mode on android14-6.1). The boot loader is unchanged, so
the ABI check against /sys/kernel/btf/vmlinux still gates every load.
"""
import argparse
import hashlib
import json
import re
import runpy
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD = runpy.run_path(str(ROOT / 'scripts/build-gki.py'))
PACKAGE = runpy.run_path(str(ROOT / 'scripts/package-module.py'))
TARGETS = BUILD['TARGETS']


def sha(data):
    return hashlib.sha256(data).hexdigest()


def devtmpfs_files(path, kmi):
    """Vendor-header devtmpfs build and the kernel symbols it needs at load."""
    data = Path(path).read_bytes()
    PACKAGE['arm64'](data)
    modinfo = runpy.run_path(str(ROOT / 'scripts/abi/prepare-device-vm.py'))['modinfo'](data)[2]
    if b'parmtype=gki:bool' not in modinfo.split(b'\0'):
        raise ValueError('devtmpfs module lacks the gki loading interface')
    nm = subprocess.run(['llvm-nm', '-u', str(path)], capture_output=True, text=True, check=True)
    symbols = sorted(set(nm.stdout.split()[1::2]))
    if not symbols:
        raise ValueError('devtmpfs module has no unresolved symbols; wrong file?')
    ko, syms = f'droidspaces_devtmpfs-{kmi}.ko', f'{kmi}.devtmpfs.syms'
    return {f'kernel/{ko}': data,
            f'kernel/{syms}': ''.join(f'{s}\n' for s in symbols).encode(),
            'kernel/devtmpfs.tsv': f'{kmi}|{ko}|{syms}\n'.encode()}, data


def package(family, label, output, devtmpfs=None):
    target = TARGETS[family]
    kmi = target['kmi']
    out = ROOT / 'out/gki' / kmi
    payload = (out / 'droidspaces_ns.ko').read_bytes()
    PACKAGE['arm64'](payload)
    build = json.loads((out / 'build.json').read_text())
    if build['sources'] != BUILD['source_hashes'](target) or build['module_sha256'] != sha(payload):
        raise ValueError(f'{kmi}: sources or payload changed since build')
    prepared = json.loads((out / 'prepared.json').read_text())
    if prepared['droidspaces_ns.ko'] != sha(payload):
        raise ValueError(f'{kmi}: ABI constraints were prepared for a different payload')
    abi = (out / f'{kmi}.abi').read_bytes()
    notes = (out / 'kernel.notes').read_bytes()
    if prepared[f'{kmi}.abi'] != sha(abi) or prepared['kernel.notes'] != sha(notes):
        raise ValueError(f'{kmi}: ABI preparation outputs changed')

    helper = (ROOT / 'out/gki/bin/abi-check').read_bytes()
    PACKAGE['arm64'](helper, executable=True)
    helper_build = json.loads((ROOT / 'out/gki/bin/build.json').read_text())
    if helper_build != dict(source_sha256=sha((ROOT / 'src/abi/check.c').read_bytes()),
                            binary_sha256=sha(helper)):
        raise ValueError('ABI checker source or binary changed since compilation')

    files = {name: (ROOT / 'kernelsu' / name).read_bytes() for name in PACKAGE['MODULE_FILES']}
    prop = files['module.prop'].decode()
    base = re.search(r'^version=(v[0-9.]+)$', prop, re.M).group(1)
    version = f'{base}-{label}'
    prop = re.sub(r'^version=.*$', f'version={version}', prop, flags=re.M)
    code = int(re.search(r'^versionCode=([0-9]+)$', prop, re.M).group(1)) + 1
    prop = re.sub(r'^versionCode=.*$', f'versionCode={code}', prop, flags=re.M)
    files['module.prop'] = prop.encode()

    ko, abiname, notesname = f'droidspaces_ns-{kmi}-gki.ko', f'{kmi}.abi', f'{kmi}.notes'
    files['bin/abi-check'] = helper
    files['kernel/' + ko] = payload
    files['kernel/' + abiname] = abi
    files['kernel/' + notesname] = notes
    files['kernel/manifest.tsv'] = f'{kmi}|{ko}|{abiname}|{notesname}\n'.encode()
    dev_note = ''
    if devtmpfs:
        dev_files, dev_data = devtmpfs_files(devtmpfs, kmi)
        files.update(dev_files)
        dev_note = (f'devtmpfs SHA-256: {sha(dev_data)} (vendor-header build, '
                    'scripts/build-samsung.py; symbols checked against kallsyms before load)\n')
    checksums = ''.join(f'{sha(data)}  {name.removeprefix("kernel/")}\n'
                        for name, data in sorted(files.items()) if name.startswith('kernel/'))
    checksums += f'{sha(helper)}  ../bin/abi-check\n'
    files['kernel/SHA256SUMS'] = checksums.encode()
    commit = subprocess.run(['git', '-C', str(ROOT), 'rev-parse', 'HEAD'],
                            capture_output=True, text=True, check=True).stdout.strip()
    files['LICENSE'] = (ROOT / 'LICENSE').read_bytes()
    files['README.md'] = (ROOT / 'README.md').read_bytes()
    files['SOURCE.txt'] = (
        'Source: https://github.com/Shikochin/Droidspaces-LKM\n'
        f'Commit: {commit}\nRelease: {version} (device test, single KMI {kmi})\n'
        f'Payload SHA-256: {sha(payload)}\n'
        f'{dev_note}'
        'Not VM-validated by this packager; validated on the device named in the label.\n'
        'The boot loader still checks the kernel BTF against the bundled ABI constraints.\n'
    ).encode()

    output.mkdir(parents=True, exist_ok=True)
    archive = output / f'Droidspaces-LKM-KernelSU-{version}.zip'
    with zipfile.ZipFile(archive, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name, data in sorted(files.items()):
            entry = zipfile.ZipInfo(name, date_time=(2026, 10, 10, 0, 0, 0))
            entry.create_system = 3
            executable = name.endswith('.sh') or name == 'bin/abi-check'
            entry.external_attr = (0o100755 if executable else 0o100644) << 16
            entry.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(entry, data)
    print(f'{archive}\n{sha(archive.read_bytes())}')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('family', choices=TARGETS)
    parser.add_argument('--label', required=True,
                        help='device tag appended to the version, e.g. samsung-e1s')
    parser.add_argument('--output', type=Path, default=ROOT / 'out/device')
    parser.add_argument('--devtmpfs', type=Path,
                        help='optional devtmpfs module (e.g. from scripts/build-samsung.py)')
    args = parser.parse_args()
    if not re.fullmatch(r'[a-z0-9][a-z0-9.-]*', args.label):
        parser.error('label must be lowercase letters, digits, dots and hyphens')
    package(args.family, args.label, args.output, args.devtmpfs)
