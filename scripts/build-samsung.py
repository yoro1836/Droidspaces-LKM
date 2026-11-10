#!/usr/bin/env python3
"""Build a module against a Samsung vendor kernel's headers inside the pinned DDK.

Samsung KDP kernels (CONFIG_KDP_CRED) keep credentials in hypervisor-protected
memory, so cred helpers such as get_cred/put_cred/override_creds must be
compiled from the vendor's KDP-aware headers. A module built from generic GKI
headers writes the protected cred directly and the device resets.

The GKI DDK cannot supply those headers, and a full vendor kernel build only to
obtain Module.symvers is slow. This script instead:

1. runs olddefconfig + modules_prepare on the vendor source with the device's
   own config (zcat /proc/config.gz), using the DDK image's clang;
2. borrows the GKI DDK's Module.symvers, whose KMI CRCs the vendor kernel
   keeps, so symbols in it carry versions;
3. builds with KBUILD_MODPOST_WARN=1. Symbols outside the GKI KMI (KDP helpers,
   unexported core symbols) stay unversioned and are resolved from the running
   kernel's kallsyms when ksud loads the module.

The vendor source tree is mounted read-only; all generated files go to --kdir.
Check that every unresolved symbol exists on the device before loading.
"""
import argparse
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = json.loads((ROOT / 'build/gki-targets.json').read_text())
MODULES = {
    'devtmpfs': ('devtmpfs_source', 'TARGET=devtmpfs', 'DEVTMPFS_DIR', 'droidspaces_devtmpfs.ko'),
    'namespace': ('source', 'TARGET=namespace', 'PORT_DIR', 'droidspaces_ns.ko'),
    'xt_addrtype': ('source', 'TARGET=xt_addrtype', 'PORT_DIR', 'xt_addrtype.ko'),
    'ip6table_nat': ('source', 'TARGET=ip6table_nat', 'PORT_DIR', 'ip6table_nat.ko'),
    'macvlan': ('source', 'TARGET=macvlan', 'PORT_DIR', 'macvlan.ko'),
    'netfilter61': ('source', 'TARGET=netfilter61', 'PORT_DIR', 'droidspaces_netfilter.ko'),
}


def docker(image, mounts, workdir, script):
    cmd = ['docker', 'run', '--rm', '--platform', 'linux/amd64']
    for host, guest, mode in mounts:
        cmd += ['-v', f'{host}:{guest}{":" + mode if mode else ""}']
    cmd += ['-w', workdir, image, 'sh', '-ec', script]
    subprocess.run(cmd, check=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('target', choices=TARGETS, help='GKI family whose DDK image and sources to use')
    parser.add_argument('--module', choices=MODULES, default='devtmpfs')
    parser.add_argument('--source', type=Path, required=True, help='vendor kernel source tree')
    parser.add_argument('--config', type=Path, required=True, help="device config (zcat /proc/config.gz)")
    parser.add_argument('--kdir', type=Path, required=True, help='output dir for the prepared vendor tree')
    parser.add_argument('--out', type=Path, help='module output dir (default out/samsung/<module>)')
    parser.add_argument('--make', action='append', default=[], metavar='VAR=VALUE',
                        help='extra make variable, e.g. --make USERNS61=1 (repeatable)')
    args = parser.parse_args()

    target = TARGETS[args.target]
    key, make_target, dir_var, ko = MODULES[args.module]
    if key not in target:
        parser.error(f'{target["kmi"]} has no {key}')
    source, kdir = args.source.resolve(), args.kdir.resolve()
    out = (args.out or ROOT / 'out/samsung' / args.module).resolve()
    if not (source / 'Makefile').is_file():
        parser.error(f'not a kernel tree: {source}')
    try:
        out_rel = out.relative_to(ROOT)
    except ValueError:
        parser.error('--out must be inside the repository')

    for var in args.make:
        if not __import__('re').fullmatch(r'[A-Z0-9_]+=[A-Za-z0-9_./-]*', var):
            parser.error(f'--make expects VAR=VALUE, got {var!r}')
    kdir.mkdir(parents=True, exist_ok=True)
    out.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(args.config, kdir / '.config')
    image = target['image']
    gki_kdir = f'/opt/ddk/kdir/{target["kmi"]}'
    llvm = 'LLVM=1 LLVM_IAS=1 ARCH=arm64'

    docker(image, [(source, '/ksrc', 'ro'), (kdir, '/kout', '')], '/ksrc',
           f'make O=/kout {llvm} olddefconfig >/kout/olddefconfig.log 2>&1\n'
           f'make O=/kout {llvm} -j8 modules_prepare >/kout/prepare.log 2>&1\n'
           f'cp {gki_kdir}/Module.symvers /kout/Module.symvers')
    docker(image, [(source, '/ksrc', 'ro'), (kdir, '/kdir', ''), (ROOT, '/module', '')], '/module',
           f'make KDIR=/kdir {make_target} {dir_var}={target[key]} '
           f'GKI_ANDROID={target["kmi"].split("-")[0]} GKI_VERSION={args.target} '
           f'OUT=/module/{out_rel} KBUILD_MODPOST_WARN=1 {" ".join(args.make)} -j8')

    module = out / ko
    unresolved = subprocess.run(['llvm-nm', '-u', str(module)], capture_output=True,
                                text=True, check=True).stdout.split()[1::2]
    print(f'\n{module}')
    print('Check each unresolved symbol on the device before loading:')
    print("  su -c 'for s in " + ' '.join(sorted(unresolved)) +
          "; do grep -q \" $s$\" /proc/kallsyms || echo MISSING $s; done'")
