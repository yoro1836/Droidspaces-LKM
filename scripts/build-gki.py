#!/usr/bin/env python3
"""Build one independent GKI namespace module using its pinned DDK image."""
import argparse
import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = json.loads((ROOT / 'build/gki-targets.json').read_text())

def source_hashes(target, source_key='source'):
    paths = [ROOT/'Makefile', ROOT/'src/gki-target.h']
    paths += [p for directory in (ROOT/target[source_key], ROOT/'vendor/kallrecon')
              for p in directory.rglob('*') if p.is_file()
              and not {'.git', '.DS_Store', '__pycache__'}.intersection(p.parts)]
    return {str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(paths)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', choices=TARGETS)
    parser.add_argument('--module', choices=('namespace', 'devtmpfs'), default='namespace',
                        help='devtmpfs builds the target\'s devtmpfs_source into <kmi>-devtmpfs')
    parser.add_argument('make_args', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    target = TARGETS[args.target]
    key = 'source' if args.module == 'namespace' else 'devtmpfs_source'
    if key not in target:
        parser.error(f'{target["kmi"]} has no {key}')
    source = ROOT / target[key]
    if not (source / 'main.c').is_file():
        parser.error(f'missing independent source set: {source}')
    if args.module == 'namespace':
        outname, ko, make = target['kmi'], 'droidspaces_ns.ko', ['TARGET=namespace', f'PORT_DIR={target[key]}']
    else:
        outname, ko, make = target['kmi']+'-devtmpfs', 'droidspaces_devtmpfs.ko', ['TARGET=devtmpfs', f'DEVTMPFS_DIR={target[key]}']
    cmd = ['docker', 'run', '--rm', '--platform', 'linux/amd64',
           '-v', f'{ROOT}:/module', '-w', '/module', target['image'],
           'make', *make,
           f'GKI_ANDROID={target["kmi"].split("-")[0]}', f'GKI_VERSION={args.target}',
           f'OUT=/module/out/gki/{outname}', *args.make_args]
    out = ROOT/'out/gki'/outname
    record = out/'build.json'
    record.unlink(missing_ok=True)
    before = source_hashes(target, key)
    subprocess.run(cmd, check=True)
    if before != source_hashes(target, key):
        raise RuntimeError('build sources changed during compilation')
    record.write_text(json.dumps(dict(target=target, sources=before,
        module_sha256=hashlib.sha256((out/ko).read_bytes()).hexdigest()),
        indent=2)+'\n')
