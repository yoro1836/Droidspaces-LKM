#!/bin/sh
# Build one of the Rust schedulers of github.com/sched-ext/scx, unmodified, as
# a static arm64 binary for droidspaces_scx.
#
#   build-rust.sh SCX_REPO NAME OUT_DIR
#
# SCX_REPO is a checkout of the scx release that goes with the kernel the
# module ports, which is 6.12: v1.0.8. Later releases keep their per-task
# data in BPF arenas, a map type of v6.9 that android14-6.1 does not have.
#
# Needs on the host: cargo with the aarch64-unknown-linux-gnu target, clang,
# libclang, aarch64-linux-gnu-gcc, the host's libelf and zlib development
# files for the build scripts, and static arm64 libelf, libz and libzstd in
# $SCX61_ARM64 (lib/ and include/; the image of contrib/scx61/Dockerfile has
# them in /arm64).
#
# SCX61_FOR_MAX=N caps a scheduler's bpf_for() loops at N rounds instead of
# 64 (compat.bpf.h). A large scheduler needs that to get under this
# verifier's limits; N has to cover the CPUs of the device.
#
# libbpf comes bundled with the libbpf-sys crate. libbpf-sys-1.4.6.patch is
# applied to cargo's unpacked copy of it, once.
set -eu
[ $# = 3 ] || { sed -n 2,6p "$0"; exit 2; }
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
scx=$(cd "$1" && pwd) name=$2
mkdir -p "$3"; out=$(cd "$3" && pwd)
arm64=${SCX61_ARM64:?directory with static arm64 libelf, libz and libzstd}
manifest=$scx/scheds/rust/$name/Cargo.toml
target=aarch64-unknown-linux-gnu

cargo fetch --manifest-path "$manifest" --target $target
sys=$(ls -d "${CARGO_HOME:-$HOME/.cargo}"/registry/src/*/libbpf-sys-1.4.6* | head -1)
if ! grep -q 'android14-6.1' "$sys/libbpf/src/libbpf.c"; then
    patch -d "$sys" -p1 < "$here/libbpf-sys-1.4.6.patch"
    cargo clean --release --target $target -p libbpf-sys --manifest-path "$manifest" 2>/dev/null || true
fi

export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc
export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc
export AR_aarch64_unknown_linux_gnu=aarch64-linux-gnu-ar
export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUSTFLAGS="-C target-feature=+crt-static -L $arm64/lib"
export LIBBPF_SYS_EXTRA_CFLAGS="-I$arm64/include"
# bpf_for() and bpf_repeat() as this verifier can take them, see compat.bpf.h
export BPF_EXTRA_CFLAGS_PRE_INCL="-include $here/compat.bpf.h -Wno-macro-redefined ${SCX61_FOR_MAX:+-DSCX61_FOR_MAX=$SCX61_FOR_MAX} ${SCX61_INLINE:+-mllvm -inline-threshold=$SCX61_INLINE}"
cargo build --release --target $target --manifest-path "$manifest"
cp "${CARGO_TARGET_DIR:-$scx/target}/$target/release/$name" "$out/"
ls -l "$out/$name"
