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
built=$(find build-producer -name 'libdisplay_producer.so*' -type f | head -1)
[[ -e $PREFIX/lib/pkgconfig/display-producer.pc && ! $built -nt $PREFIX/lib/libdisplay_producer.so ]] ||
    sudo cmake --install build-producer

# The patch is put on again only when it changed. Undoing the old one touches
# just the files it had modified, so everything else stays built.
stamp="$PHOC_TAG $ANLAND_REV $(sha256sum < "$HERE/phoc-anland.patch")"
if [[ $(cat phoc/.anland-stamp 2>/dev/null) != "$stamp" ]]; then
    # not the wrap file: touching it would cost a whole wlroots rebuild
    git -C phoc checkout -q -f -- . ':!subprojects/wlroots.wrap'
    rm -rf phoc/src/anland/mango phoc/src/anland/{text-stub.c,glue.c,unhook.c,phoc-anland.h}
    git -C phoc apply "$HERE/phoc-anland.patch"
    echo "$stamp" > phoc/.anland-stamp
fi
# Mango's backend goes in unchanged.
mkdir -p phoc/src/anland
for f in anland.c output.c buffer.c input.c clipboard.c anland.h internal.h text.h; do
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
if [[ ! -x $PREFIX/bin/phoc || build-phoc/src/phoc -nt $PREFIX/bin/phoc ||
      -n $(find build-phoc -name 'libphoc.so*' -newer "$PREFIX/bin/phoc" -print -quit) ]]; then
    sudo meson install -C build-phoc --no-rebuild
    sudo touch "$PREFIX/bin/phoc"
fi
echo "installed: $PREFIX/bin/phoc"
