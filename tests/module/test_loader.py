#!/usr/bin/env python3
"""Exercise boot-loader decisions without loading anything into the host kernel."""
import hashlib
import os
from pathlib import Path
import shutil
import shlex
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
RELEASE = '6.12.69-android16-6-g242e1a07f878-ab15865446-4k'


class LoaderTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.module = self.root / 'module'
        shutil.copytree(ROOT / 'kernelsu', self.module)
        kernel = self.module / 'kernel'
        kernel.mkdir()
        self.kmis = ['android12-5.10', 'android13-5.15', 'android14-6.1',
                     'android15-6.6', 'android16-6.12', 'android17-6.18']
        rows, sums = [], []
        for kmi in self.kmis:
            ko, abi, notes = f'droidspaces_ns-{kmi}.ko', f'{kmi}.abi', f'{kmi}.notes'
            for name in (ko, abi, notes):
                data = f'fake {name}, never passed to the real kernel'.encode()
                (kernel / name).write_bytes(data)
                sums.append(f'{hashlib.sha256(data).hexdigest()}  {name}\n')
            rows.append(f'{kmi}|{ko}|{abi}|{notes}\n')
        (kernel / 'manifest.tsv').write_text(''.join(rows))
        (kernel / 'SHA256SUMS').write_text(''.join(sums))
        (self.module / 'bin').mkdir()
        checker = self.module / 'bin/abi-check'
        checker.write_text('#!/bin/sh\n[ "$FAKE_MODE" != abi_error ]\n')
        checker.chmod(0o755)
        (self.root / 'btf').write_bytes(b'mocked kernel BTF')
        (self.root / 'kallsyms').write_text(
            '0000000000000000 T kdp_usecount_inc\n0000000000000000 D devices_kset\n'
            '0000000000000000 t helper\t[kernelsu]\n')
        self.ksud = self.root / 'ksud'
        self.ksud.write_text('''#!/bin/sh
if [ "$1" = module ]; then
    [ "$FAKE_CONFIG" != fail ] || exit 1
    printf '%s\\n' "$6" > "$FAKE_ROOT/description"
    exit 0
fi
[ "$1" = insmod ] || exit 2
printf '%s\\n' "$*" >> "$FAKE_ROOT/insmod-calls"
case "$2" in
    *extra_bad*) exit 5;;
    *extra*)
        ds_extra=${2##*/}; ds_extra=${ds_extra%.ko}
        mkdir -p "$FAKE_ROOT/modules/$(printf '%s' "$ds_extra" | tr - _)"
        exit 0;;
    *devtmpfs*)
        [ "$FAKE_DEV" != error ] || exit 19
        mkdir -p "$FAKE_ROOT/devsys/parameters"
        printf 'Y\\n' > "$FAKE_ROOT/devsys/parameters/ready"
        if [ "$FAKE_DEV" = errors ]; then echo 3; else echo 0; fi > "$FAKE_ROOT/devsys/parameters/errors"
        exit 0;;
esac
[ "$FAKE_MODE" != error ] || exit 17
[ "$FAKE_MODE" != incomplete ] || exit 0
mkdir -p "$FAKE_ROOT/sys/parameters" "$FAKE_ROOT/ns"
printf 'Y\\n' > "$FAKE_ROOT/sys/parameters/activate"
touch "$FAKE_ROOT/ns/pid" "$FAKE_ROOT/ns/pid_for_children" "$FAKE_ROOT/ns/ipc"
[ "$FAKE_USERNS" != 1 ] || touch "$FAKE_ROOT/ns/user"
''')
        self.ksud.chmod(0o755)

    def add_devtmpfs(self, kmi='android16-6.12', symbols=('kdp_usecount_inc', 'devices_kset')):
        kernel = self.module / 'kernel'
        ko, syms = f'droidspaces_devtmpfs-{kmi}.ko', f'{kmi}.devtmpfs.syms'
        (kernel / ko).write_bytes(b'fake devtmpfs, never passed to the real kernel')
        (kernel / syms).write_text(''.join(f'{s}\n' for s in symbols))
        (kernel / 'devtmpfs.tsv').write_text(f'{kmi}|{ko}|{syms}\n')
        sums = (kernel / 'SHA256SUMS').read_text()
        for name in (ko, syms, 'devtmpfs.tsv'):
            sums += f'{hashlib.sha256((kernel / name).read_bytes()).hexdigest()}  {name}\n'
        (kernel / 'SHA256SUMS').write_text(sums)

    def add_ns_symbols(self, symbols, kmi='android16-6.12'):
        kernel = self.module / 'kernel'
        name = f'droidspaces_ns-{kmi}.ko.syms'
        (kernel / name).write_text(''.join(f'{s}\n' for s in symbols))
        sums = (kernel / 'SHA256SUMS').read_text()
        sums += f'{hashlib.sha256((kernel / name).read_bytes()).hexdigest()}  {name}\n'
        (kernel / 'SHA256SUMS').write_text(sums)

    def run_loader(self, mode='success', release=RELEASE, config='ok', command='ds_load', dev='ok', userns=False):
        script = '''
MODDIR=$FAKE_ROOT/module
. "$MODDIR/common.sh"
DS_KSUD=$FAKE_ROOT/ksud
DS_BTF=$FAKE_ROOT/btf
DS_KERNEL_NOTES=$FAKE_ROOT/kernel.notes
DS_MODULE_SYS=$FAKE_ROOT/sys
DS_PROC_NS=$FAKE_ROOT/ns
DS_DEV_SYS=$FAKE_ROOT/devsys
DS_SYS_MODULES=$FAKE_ROOT/modules
DS_KALLSYMS=$FAKE_ROOT/kallsyms
uname() {
    case "$1" in
        -m) printf 'aarch64\\n';;
        -r) printf '%s\\n' "$FAKE_RELEASE";;
    esac
}
''' + command
        shell = shlex.split(os.environ.get('LOADER_TEST_SHELL', 'sh'))
        result = subprocess.run([*shell, '-c', script], text=True, capture_output=True,
                                env={**os.environ, 'FAKE_ROOT': str(self.root),
                                     'FAKE_MODE': mode, 'FAKE_RELEASE': release, 'FAKE_CONFIG': config,
                                     'FAKE_DEV': dev, 'FAKE_USERNS': '1' if userns else '0'})
        self.status = (self.module / 'status.txt').read_text()
        return result

    def test_load_and_verify_activation(self):
        r = self.run_loader()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('[已加载]', self.status)
        self.assertIn('activate=1', (self.root / 'insmod-calls').read_text())
        self.assertEqual(self.status, (self.root / 'description').read_text())
        self.assertIn('description=[待加载]', (self.module / 'module.prop').read_text())

    def test_repeat_does_not_load_twice(self):
        self.assertEqual(self.run_loader().returncode, 0)
        self.assertEqual(self.run_loader().returncode, 0)
        self.assertEqual(len((self.root / 'insmod-calls').read_text().splitlines()), 1)
        self.assertIn('本次开机已加载', self.status)

    def test_wrong_kernel_rejected(self):
        self.assertNotEqual(self.run_loader(release='6.12.other').returncode, 0)
        self.assertIn('[不支持]', self.status)
        self.assertFalse((self.root / 'insmod-calls').exists())

    def test_wrong_android_kmi_rejected(self):
        self.assertNotEqual(self.run_loader(release="5.15.100-android14-0-g123").returncode, 0)
        self.assertFalse((self.root / 'insmod-calls').exists())

    def test_corrupt_payload_rejected(self):
        (self.module / 'kernel/droidspaces_ns-android16-6.12.ko').write_bytes(b'corrupt')
        self.assertNotEqual(self.run_loader().returncode, 0)
        self.assertIn('SHA-256', self.status)
        self.assertFalse((self.root / 'insmod-calls').exists())

    def test_all_six_kmis_select_distinct_payloads(self):
        for kmi in self.kmis:
            with self.subTest(kmi=kmi):
                shutil.rmtree(self.root / 'sys', ignore_errors=True)
                android, version = kmi.split('-')
                result = self.run_loader(release=f'{version}.99-{android}-0-g123')
                self.assertEqual(result.returncode, 0, result.stderr)
                call = (self.root / 'insmod-calls').read_text().splitlines()[-1]
                self.assertIn(f'droidspaces_ns-{kmi}.ko gki=1 activate=1', call)
                self.assertIn(kmi, self.status)

    def test_abi_failure_stops_before_insmod(self):
        self.assertNotEqual(self.run_loader(mode='abi_error').returncode, 0)
        self.assertIn('[不兼容]', self.status)
        self.assertFalse((self.root / 'insmod-calls').exists())

    def test_missing_btf_is_explicit(self):
        (self.root / 'btf').unlink()
        self.assertNotEqual(self.run_loader().returncode, 0)
        self.assertIn('[不兼容]', self.status)
        self.assertFalse((self.root / 'insmod-calls').exists())

    def test_duplicate_manifest_entry_rejected(self):
        manifest = self.module / 'kernel/manifest.tsv'
        manifest.write_text(manifest.read_text() * 2)
        self.assertNotEqual(self.run_loader().returncode, 0)
        self.assertFalse((self.root / 'insmod-calls').exists())

    def test_no_btf_accepts_exact_kernel_notes(self):
        (self.root / 'btf').unlink()
        shutil.copyfile(self.module / 'kernel/android16-6.12.notes', self.root / 'kernel.notes')
        result = self.run_loader()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('exact validated kernel notes matched', result.stdout)

    def test_no_btf_rejects_different_kernel_build(self):
        (self.root / 'btf').unlink()
        (self.root / 'kernel.notes').write_bytes(b'a different kernel build')
        self.assertNotEqual(self.run_loader().returncode, 0)
        self.assertFalse((self.root / 'insmod-calls').exists())

    def test_notes_do_not_override_failed_btf_check(self):
        shutil.copyfile(self.module / 'kernel/android16-6.12.notes', self.root / 'kernel.notes')
        self.assertNotEqual(self.run_loader(mode='abi_error').returncode, 0)
        self.assertFalse((self.root / 'insmod-calls').exists())

    def test_insmod_failure_visible(self):
        self.assertNotEqual(self.run_loader(mode='error').returncode, 0)
        self.assertIn('返回 17', self.status)

    def test_success_exit_without_activation_is_failure(self):
        self.assertNotEqual(self.run_loader(mode='incomplete').returncode, 0)
        self.assertIn('检查未通过', self.status)

    def test_inactive_existing_module_is_not_reloaded(self):
        (self.root / 'sys/parameters').mkdir(parents=True)
        (self.root / 'sys/parameters/activate').write_text('N\n')
        self.assertNotEqual(self.run_loader().returncode, 0)
        self.assertIn('未激活', self.status)
        self.assertFalse((self.root / 'insmod-calls').exists())

    def test_missing_loader_uses_visible_fallback(self):
        self.ksud.unlink()
        self.assertNotEqual(self.run_loader().returncode, 0)
        self.assertIn('找不到', self.status)
        self.assertIn('description=[加载失败]', (self.module / 'module.prop').read_text())

    def test_fallback_and_boot_reset(self):
        self.assertEqual(self.run_loader(config='fail').returncode, 0)
        self.assertIn('description=[已加载]', (self.module / 'module.prop').read_text())
        self.assertEqual(self.run_loader(config='fail', command="ds_status '[待加载] 本次开机尚未加载'").returncode, 0)
        self.assertIn('description=[待加载]', (self.module / 'module.prop').read_text())
        self.assertEqual((self.module / 'module.prop').read_text().count('description='), 1)

    def add_extras(self, names, kmi='android16-6.12', symbols=None):
        kernel = self.module / 'kernel'
        rows = ''
        for name in names:
            (kernel / f'{name}.ko').write_bytes(b'fake extra module')
            rows += f'{kmi}|{name}.ko\n'
            added = [f'{name}.ko']
            if symbols and name in symbols:
                (kernel / f'{name}.ko.syms').write_text(''.join(f'{s}\n' for s in symbols[name]))
                added.append(f'{name}.ko.syms')
            with (kernel / 'SHA256SUMS').open('a') as sums:
                for item in added:
                    sums.write(f'{hashlib.sha256((kernel / item).read_bytes()).hexdigest()}  {item}\n')
        (kernel / 'extras.tsv').write_text(rows)
        with (kernel / 'SHA256SUMS').open('a') as sums:
            sums.write(f'{hashlib.sha256(rows.encode()).hexdigest()}  extras.tsv\n')

    def test_extras_load_in_order_after_namespace(self):
        self.add_extras(['extra_a', 'extra-b'])
        r = self.run_loader()
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = (self.root / 'insmod-calls').read_text().splitlines()
        self.assertEqual(len(calls), 3)
        self.assertIn('extra_a.ko', calls[1])
        self.assertIn('extra-b.ko', calls[2])
        self.assertIn('[已加载]', self.status)
        self.assertIn('及 2 个扩展模块', self.status)

    def test_extra_failure_keeps_namespace_and_other_extras(self):
        self.add_extras(['extra_bad', 'extra_a'])
        r = self.run_loader()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('[部分加载]', self.status)
        self.assertIn('扩展模块未加载：extra_bad', self.status)
        self.assertTrue((self.root / 'modules/extra_a').is_dir())

    def test_extra_missing_symbol_skips_insmod(self):
        self.add_extras(['extra_a'], symbols={'extra_a': ('kdp_usecount_inc', 'not_in_this_kernel')})
        r = self.run_loader()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(len((self.root / 'insmod-calls').read_text().splitlines()), 1)
        self.assertIn('[部分加载]', self.status)

    def test_extras_already_loaded_are_not_reloaded(self):
        self.add_extras(['extra_a'])
        self.assertEqual(self.run_loader().returncode, 0)
        self.assertEqual(self.run_loader().returncode, 0)
        self.assertEqual(len((self.root / 'insmod-calls').read_text().splitlines()), 2)
        self.assertIn('及 1 个扩展模块 已激活（本次开机已加载）', self.status)

    def test_extras_for_another_kmi_are_ignored(self):
        self.add_extras(['extra_a'], kmi='android14-6.1')
        self.assertEqual(self.run_loader().returncode, 0)
        self.assertEqual(len((self.root / 'insmod-calls').read_text().splitlines()), 1)
        self.assertNotIn('扩展模块', self.status)

    def test_without_devtmpfs_manifest_status_is_unchanged(self):
        self.assertEqual(self.run_loader().returncode, 0)
        self.assertIn('PID / IPC namespace 已激活；', self.status)
        self.assertNotIn('devtmpfs', self.status)

    def test_devtmpfs_loads_after_namespace(self):
        self.add_devtmpfs()
        r = self.run_loader()
        self.assertEqual(r.returncode, 0, r.stderr)
        calls = (self.root / 'insmod-calls').read_text().splitlines()
        self.assertEqual(len(calls), 2)
        self.assertIn('droidspaces_ns-android16-6.12.ko', calls[0])
        self.assertIn('droidspaces_devtmpfs-android16-6.12.ko gki=1', calls[1])
        self.assertIn('[已加载]', self.status)
        self.assertIn('与 devtmpfs', self.status)

    def test_devtmpfs_missing_symbol_skips_insmod(self):
        self.add_devtmpfs(symbols=('kdp_usecount_inc', 'not_in_this_kernel'))
        r = self.run_loader()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('not_in_this_kernel', r.stdout)
        self.assertEqual(len((self.root / 'insmod-calls').read_text().splitlines()), 1)
        self.assertIn('[部分加载]', self.status)
        self.assertIn('符号缺失', self.status)

    def test_devtmpfs_symbol_match_is_exact(self):
        # 'helper' exists only as a module symbol line ending in [kernelsu].
        self.add_devtmpfs(symbols=('helper',))
        self.run_loader()
        self.assertIn('符号缺失', self.status)

    def test_devtmpfs_failure_keeps_namespace_result(self):
        self.add_devtmpfs()
        self.assertEqual(self.run_loader(dev='error').returncode, 0)
        self.assertIn('[部分加载]', self.status)
        self.assertIn('返回 19', self.status)
        self.assertTrue((self.root / 'sys/parameters/activate').exists())

    def test_devtmpfs_errors_reported(self):
        self.add_devtmpfs()
        self.run_loader(dev='errors')
        self.assertIn('[部分加载]', self.status)

    def test_devtmpfs_loaded_once_per_boot(self):
        self.add_devtmpfs()
        self.assertEqual(self.run_loader().returncode, 0)
        self.assertEqual(self.run_loader().returncode, 0)
        self.assertEqual(len((self.root / 'insmod-calls').read_text().splitlines()), 2)
        self.assertIn('与 devtmpfs 已激活（本次开机已加载）', self.status)

    def test_devtmpfs_payload_covered_by_checksums(self):
        self.add_devtmpfs()
        (self.module / 'kernel/droidspaces_devtmpfs-android16-6.12.ko').write_bytes(b'corrupt')
        self.assertNotEqual(self.run_loader().returncode, 0)
        self.assertIn('SHA-256', self.status)
        self.assertFalse((self.root / 'insmod-calls').exists())

    def test_ns_symbols_checked_before_insmod(self):
        self.add_ns_symbols(['kdp_usecount_inc', 'missing_in_kernel'])
        r = self.run_loader()
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('[不兼容]', self.status)
        self.assertIn('missing_in_kernel', r.stdout)
        self.assertFalse((self.root / 'insmod-calls').exists())

    def test_ns_symbols_present_loads(self):
        self.add_ns_symbols(['kdp_usecount_inc', 'devices_kset'])
        r = self.run_loader()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('[已加载]', self.status)

    def test_user_namespace_shown_in_status(self):
        r = self.run_loader(userns=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn('PID / IPC / user namespace 已激活', self.status)


if __name__ == '__main__':
    unittest.main()
