#!/bin/sh
# Build one of the kernel tree's tools/sched_ext schedulers, unmodified, as a
# static arm64 binary for droidspaces_scx.
#
#   build-upstream.sh SCX_REPO LIBBPF_REPO SCHED_DIR NAME OUT_DIR
#
# SCX_REPO is a checkout of github.com/sched-ext/scx (headers and vmlinux.h),
# LIBBPF_REPO one of github.com/libbpf/libbpf with libbpf-android14-6.1.patch
# applied, SCHED_DIR holds NAME.bpf.c and NAME.c from tools/sched_ext.
set -eu
[ $# = 5 ] || { sed -n 2,9p "$0"; exit 2; }
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
scx=$(cd "$1" && pwd) libbpf=$(cd "$2" && pwd) src=$(cd "$3" && pwd) name=$4
mkdir -p "$5"; out=$(cd "$5" && pwd)
docker build -q --platform linux/amd64 -t droidspaces-scx-build:local "$here" >/dev/null
docker run --rm --platform linux/amd64 -v "$scx:/scx:ro" -v "$libbpf:/libbpf:ro" \
    -v "$src:/src:ro" -v "$out:/out" -e NAME="$name" droidspaces-scx-build:local sh -eu -c '
    cp -r /libbpf /tmp/libbpf
    make -s -C /tmp/libbpf/src CC=aarch64-linux-gnu-gcc BUILD_STATIC_ONLY=1 OBJDIR=/tmp/lbobj \
        DESTDIR=/tmp/lb PREFIX=/usr LIBDIR=/usr/lib EXTRA_CFLAGS=-I/arm64/include install >/dev/null
    inc="-I/scx/scheds/include -I/scx/scheds/include/bpf-compat -I/tmp/lb/usr/include"
    clang -O2 -g -target bpf -D__TARGET_ARCH_arm64 -mcpu=v3 -Wno-compare-distinct-pointer-types \
        $inc -I/scx/scheds/vmlinux/arch/arm64 -c /src/$NAME.bpf.c -o /tmp/$NAME.tmp.o
    bpftool gen object /out/$NAME.bpf.o /tmp/$NAME.tmp.o
    bpftool gen skeleton /out/$NAME.bpf.o name $NAME > /tmp/$NAME.bpf.skel.h
    aarch64-linux-gnu-gcc -static -O2 $inc -I/tmp -I/arm64/include \
        /src/$NAME.c -o /out/$NAME -L/tmp/lb/usr/lib -L/arm64/lib -lbpf -lelf -lz -lzstd
    '
ls -l "$out/$name"
