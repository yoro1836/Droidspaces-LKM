#!/usr/bin/env bash
# Build phoc 0.57 with the Anland backend into a private prefix, beside the
# distribution's own phoc. Run as a normal user with sudo, on Arch Linux.
# Safe to run again: only what changed since the last run is rebuilt.
set -euo pipefail

PREFIX=${PHOC_ANLAND_PREFIX:-/usr/lib/phoc-anland}
WORK=${WORK:-$HOME/.cache/phoc-anland}
ANLAND_REV=a23ccd8
PHOC_TAG=v0.57.0
HERE=$(cd "$(dirname "$0")" && pwd)

DEPS=(base-devel git cmake meson ninja pkgconf
    wayland wayland-protocols wayland-utils libxkbcommon pixman libdrm libinput seatd mesa libglvnd
    libdisplay-info hwdata libliftoff lcms2 vulkan-headers vulkan-icd-loader glslang
    libxcb xcb-util-wm xcb-util-renderutil xcb-util-errors xorg-xwayland
    glib2 glib2-devel json-glib gnome-desktop gsettings-desktop-schemas dconf
    systemd-libs libpipewire libpulse)
# pacman -T prints what is missing and nothing else, so a second run needs no sudo.
missing=$(pacman -T "${DEPS[@]}" || true)
[[ -z $missing ]] || sudo pacman -S --needed --noconfirm $missing

mkdir -p "$WORK" && cd "$WORK"
[[ -d anland ]] || git clone https://github.com/SuperTurtleDev/anland.git
[[ $(git -C anland rev-parse --short=7 HEAD) == "$ANLAND_REV" ]] || git -C anland checkout -q "$ANLAND_REV"
[[ -d phoc ]] || git clone --depth 1 --branch "$PHOC_TAG" https://gitlab.gnome.org/World/Phosh/phoc.git

# Copy only when the content differs, so an unchanged file keeps its mtime
# and ninja leaves its object alone.
put() { cmp -s "$1" "$2" || cp "$1" "$2"; }

# The producer library: what a compositor talks to Anland through.
if [[ ! -f build-producer/build.ninja ]]; then
    mkdir -p producer
    printf 'cmake_minimum_required(VERSION 3.19)\nproject(anland_public LANGUAGES C)\nadd_subdirectory(%s/anland/libdisplay_producer producer)\n' "$WORK" > producer/CMakeLists.txt
    cmake -S producer -B build-producer -G Ninja -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_INSTALL_LIBDIR=lib
fi
cmake --build build-producer
# Whether an install is due is read off a stamp in the build directory, not
# off the installed files: their mtimes are copied and rounded on the way, so
# "is the build newer" came out true on some filesystems and sudo ran for
# nothing.
newer() { [[ ! -e $1/.installed || -n $(find "$1" -type f -newer "$1/.installed" \( -name "$2" -o -name "$3" \) -print -quit) ]]; }
if [[ ! -e $PREFIX/lib/pkgconfig/display-producer.pc ]] || newer build-producer 'libdisplay_producer.so*' '*.pc'; then
    sudo cmake --install build-producer
    touch build-producer/.installed
fi

# The patch is put on again only when it changed. Undoing the old one touches
# just the files it had modified, so everything else stays built.
stamp="$PHOC_TAG $ANLAND_REV $(sha256sum < "$HERE/phoc-anland.patch")"
if [[ $(cat phoc/.anland-stamp 2>/dev/null) != "$stamp" ]]; then
    # Keep the files the old patch produced. Whatever the new patch produces
    # byte for byte the same gets its old mtime back, so a change in one file
    # of the patch recompiles that file and not all it touches.
    mapfile -t patched < <(git -C phoc apply --numstat "$HERE/phoc-anland.patch" | cut -f3)
    rm -rf .prev && mkdir .prev
    for f in "${patched[@]}"; do
        [[ -f phoc/$f ]] && { mkdir -p ".prev/$(dirname "$f")"; cp -p "phoc/$f" ".prev/$f"; }
    done
    # not the wrap file: touching it would cost a whole wlroots rebuild
    git -C phoc checkout -q -f -- . ':!subprojects/wlroots.wrap'
    rm -rf phoc/src/anland/mango phoc/src/anland/{text-stub.c,glue.c,unhook.c,phoc-anland.h}
    git -C phoc apply "$HERE/phoc-anland.patch"
    for f in "${patched[@]}"; do
        [[ -f .prev/$f ]] && cmp -s ".prev/$f" "phoc/$f" && touch -r ".prev/$f" "phoc/$f"
    done
    rm -rf .prev
    echo "$stamp" > phoc/.anland-stamp
fi
# Mango's backend goes in unchanged.
mkdir -p phoc/src/anland
for f in anland.c output.c buffer.c input.c clipboard.c text.c anland.h internal.h text.h; do
    put "anland/producers/mango/anland_backend/$f" "phoc/src/anland/$f"
done

# wlroots is built into phoc, with Anland's swapchain patch on top of phoc's own.
wl=phoc/subprojects/packagefiles/wlroots/9000-anland-external-swapchain.patch
if ! cmp -s anland/producers/mango/Arch_v5/wlroots.patch "$wl" || ! grep -q 9000-anland phoc/subprojects/wlroots.wrap; then
    cp anland/producers/mango/Arch_v5/wlroots.patch "$wl"
    grep -q 9000-anland phoc/subprojects/wlroots.wrap ||
        sed -i 's|^\(  wlroots/0001-.*\)$|\1,\n  wlroots/9000-anland-external-swapchain.patch|' phoc/subprojects/wlroots.wrap
    # meson applies wrap patches only when it unpacks the subproject
    rm -rf phoc/subprojects/wlroots-0.20.x build-phoc
fi

[[ -f build-phoc/build.ninja ]] ||
    PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig" meson setup build-phoc phoc \
        --prefix="$PREFIX" --buildtype=release -Danland=enabled -Dembed-wlroots=enabled \
        -Dtests=false -Dman=false -Dgtk_doc=false \
        -Dc_link_args="-Wl,-rpath,$PREFIX/lib"
meson compile -C build-phoc
if [[ ! -x $PREFIX/bin/phoc ]] || newer build-phoc phoc 'libphoc.so*'; then
    sudo meson install -C build-phoc --no-rebuild
    touch build-phoc/.installed
fi
echo "installed: $PREFIX/bin/phoc"
