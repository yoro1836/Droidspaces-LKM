#!/bin/sh
# Run only in QEMU: load droidspaces_scx.ko into the android14-6.1 GKI kernel
# and drive it with tests/vm/scx.c. Uses the image from Dockerfile.cross, so
# the host needs no arm64 binfmt handler.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
log_dir=${DS_SCX_LOG_DIR:-out/scx/vm}
case "$log_dir" in out/*) ;; *) exit 2;; esac
case "$log_dir" in *..*) exit 2;; esac
mkdir -p "$root/$log_dir"
docker run --rm --platform linux/amd64 -v "$root:/work" \
    -e KERNEL="${DS_SCX_KERNEL:-/work/out/gki/android14-6.1/Image}" \
    -e MODULE="${DS_SCX_MODULE:-/work/out/gki/android14-6.1-scx/droidspaces_scx.ko}" \
    -e LOG="/work/$log_dir/console.log" \
    droidspaces-lkm-vm-cross:local sh -eu -c '
    test -r "$KERNEL" && test -r "$MODULE"
    mkdir -p /tmp/root/bin /tmp/root/dev /tmp/root/proc /tmp/root/sys
    cp /bin/busybox /tmp/root/bin/ 2>/dev/null || cp /usr/bin/busybox /tmp/root/bin/
    for a in $(cat /work/tests/vm/busybox-applets); do test "$a" = busybox || ln -s busybox /tmp/root/bin/$a; done
    aarch64-linux-gnu-gcc -static -O2 -Wall -Wextra -Werror /work/tests/vm/load-module.c -o /tmp/root/load-module
    aarch64-linux-gnu-gcc -static -O2 -Wall -Wextra -Werror /work/tests/vm/scx.c -o /tmp/root/scx-test
    clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 -I/usr/include/aarch64-linux-gnu \
        -c /work/tests/vm/scx-sched.bpf.c -o /tmp/root/scx-sched.bpf.o
    aarch64-linux-gnu-gcc -static -O2 -Wall /work/tests/vm/scx-load.c -o /tmp/root/scx-load \
        -lbpf -lelf -lz -lzstd
    aarch64-linux-gnu-gcc -static -O2 -Wall -Wextra -Werror /work/contrib/scx61/scx-run.c -o /tmp/root/scx-run
    # Upstream scx_simple, when contrib/scx61/build-upstream.sh has built it.
    if [ -x /work/out/scx/upstream/scx_simple ]; then cp /work/out/scx/upstream/scx_simple /tmp/root/; fi
    cp "$MODULE" /tmp/root/scx.ko
    cp /work/tests/vm/scx-init /tmp/root/init
    chmod +x /tmp/root/init
    mknod /tmp/root/dev/console c 5 1
    mknod /tmp/root/dev/null c 1 3
    cd /tmp/root
    find . -print0 | cpio --null -o -H newc >/tmp/initramfs
    timeout 300 qemu-system-aarch64 -machine virt -cpu max -m 1024 -smp 2 \
        -nographic -monitor none -nic none -no-reboot -kernel "$KERNEL" \
        -initrd /tmp/initramfs \
        -append "console=ttyAMA0 rdinit=/init nokaslr selinux=0 panic=-1" >"$LOG" 2>&1
    ' || true
log="$root/$log_dir/console.log"
grep -aE "^(SCX|attaches=|kfunc_errors=|DS_SCX|libbpf)" "$log" || true
if ! grep -q "^DS_SCX_VM_RESULT=0" "$log" ||
   grep -Eq "WARNING: CPU:|BUG:|Oops:|Kernel panic|bad: scheduling|Unable to handle|rcu.*stall" "$log"; then
    tail -80 "$log"; exit 1
fi
printf "scx VM test passed: %s\n" "$log"
