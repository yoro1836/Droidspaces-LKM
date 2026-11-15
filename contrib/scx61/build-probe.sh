#!/bin/sh
# Compile one BPF scheduler source, and the load-only probe, to put the object
# before the verifier of a device or of the test VM (scx-probe.c).
#
#   build-probe.sh SCX_REPO LIBBPF_REPO SOURCE.bpf.c NAME OUT_DIR
#
# SCX_REPO is a checkout of github.com/sched-ext/scx that has the headers the
# source was written against, LIBBPF_REPO one of github.com/libbpf/libbpf with
# libbpf-android14-6.1.patch applied.
set -eu
[ $# = 5 ] || { sed -n 2,9p "$0"; exit 2; }
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
scx=$(cd "$1" && pwd) libbpf=$(cd "$2" && pwd) name=$4
src=$(cd "$(dirname "$3")" && pwd)/$(basename "$3")
mkdir -p "$5"; out=$(cd "$5" && pwd)
docker build -q --platform linux/amd64 -t droidspaces-scx-build:local "$here" >/dev/null
docker run --rm --platform linux/amd64 -v "$scx:/scx:ro" -v "$libbpf:/libbpf:ro" -v "$here:/here:ro" \
    -v "$src:/src.bpf.c:ro" -v "$(dirname "$src"):/srcdir:ro" -v "$out:/out" -e NAME="$name" \
    droidspaces-scx-build:local sh -eu -c '
    cp -r /libbpf /tmp/libbpf
    make -s -C /tmp/libbpf/src CC=aarch64-linux-gnu-gcc BUILD_STATIC_ONLY=1 OBJDIR=/tmp/lbobj \
        DESTDIR=/tmp/lb PREFIX=/usr LIBDIR=/usr/lib EXTRA_CFLAGS=-I/arm64/include install >/dev/null
    arch=/scx/scheds/include/arch/arm64
    [ -d $arch ] || arch=/scx/scheds/vmlinux/arch/arm64
    inc="-I/srcdir -I/scx/scheds/include -I$arch -I/scx/scheds/include/bpf-compat -I/tmp/lb/usr/include"
    clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 -mcpu=v3 -Wno-compare-distinct-pointer-types \
        -Wno-macro-redefined -include /here/compat.bpf.h $inc -idirafter /usr/aarch64-linux-gnu/include \
        -c /src.bpf.c -o /tmp/$NAME.tmp.o
    bpftool gen object /out/$NAME.bpf.o /tmp/$NAME.tmp.o
    aarch64-linux-gnu-gcc -static -O2 -I/tmp/lb/usr/include -I/arm64/include /here/scx-probe.c \
        -o /out/scx-probe -L/tmp/lb/usr/lib -L/arm64/lib -lbpf -lelf -lz -lzstd
    '
ls -l "$out/$name.bpf.o"
