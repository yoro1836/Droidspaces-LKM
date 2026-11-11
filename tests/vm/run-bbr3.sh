#!/bin/sh
# Run only in QEMU: load tcp_bbr3.ko into the android14-6.1 GKI kernel and
# drive it with tests/vm/bbr3.c over loopback, plain and through netem.
set -eu
root=$(CDPATH= cd -- "$(dirname -- "$0")/../.." && pwd)
log_dir=${DS_BBR3_LOG_DIR:-out/bbr3/vm}
case "$log_dir" in out/*) ;; *) exit 2;; esac
case "$log_dir" in *..*) exit 2;; esac
mkdir -p "$root/$log_dir"
docker run --rm --platform linux/arm64 -v "$root:/work" \
    -e KERNEL="${DS_BBR3_KERNEL:-/work/out/gki/android14-6.1/Image}" \
    -e MODULE="${DS_BBR3_MODULE:-/work/out/samsung/tcp_bbr3/tcp_bbr3.ko}" \
    -e LOG="/work/$log_dir/console.log" \
    droidspaces-lkm-vm:local sh -eu -c '
    test -r "$KERNEL" && test -r "$MODULE"
    mkdir -p /tmp/root/bin /tmp/root/dev /tmp/root/proc /tmp/root/sys
    cp /usr/bin/busybox /tmp/root/bin/
    for a in $(busybox --list); do test "$a" = busybox || ln -s busybox /tmp/root/bin/$a; done
    gcc -static -O2 -Wall -Wextra -Werror -pthread /work/tests/vm/bbr3.c -o /tmp/root/bbr3
    cp "$MODULE" /tmp/root/tcp_bbr3.ko
    cp /work/tests/vm/bbr3-init /tmp/root/init
    chmod +x /tmp/root/init
    mknod /tmp/root/dev/console c 5 1
    mknod /tmp/root/dev/null c 1 3
    cd /tmp/root
    find . -print0 | cpio --null -o -H newc >/tmp/initramfs
    timeout 900 qemu-system-aarch64 -machine virt -cpu max -m 1024 -smp 2 \
        -nographic -monitor none -nic none -no-reboot -kernel "$KERNEL" \
        -initrd /tmp/initramfs \
        -append "console=ttyAMA0 rdinit=/init nokaslr selinux=0 panic=-1" >"$LOG" 2>&1
    '
log="$root/$log_dir/console.log"
grep -E "^(BBR3 (plain|delay|lossy|ecn)|available:|DS_BBR3)" "$log" || true
for marker in "BBR3 plain: PASS" "BBR3 delay: PASS" "BBR3 lossy: PASS" "BBR3 ecn: PASS" \
    DS_BBR3_UNLOAD_PASS DS_BBR3_ECN_UNLOAD_PASS DS_BBR3_VM_RESULT=0; do
    grep -q "^$marker" "$log" || { tail -60 "$log"; exit 1; }
done
if grep -Eq "WARNING: CPU:|BUG:|Oops:|Kernel panic|refcount_t:|Unable to handle" "$log"; then
    tail -80 "$log"; exit 1
fi
printf "bbr3 VM test passed: %s\n" "$log"
