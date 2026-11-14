#!/usr/bin/env bash
# Build phoc 0.57 with the Anland backend into a private prefix, beside the
# distribution's own phoc. Run as a normal user with sudo, on Arch Linux.
#   ./build.sh            build and install
#   ./build.sh --deps     only install the build dependencies
set -euo pipefail

PREFIX=${PHOC_ANLAND_PREFIX:-/usr/lib/phoc-anland}
WORK=${WORK:-$HOME/.cache/phoc-anland}
ANLAND_REV=a23ccd8
PHOC_TAG=v0.57.0
HERE=$(cd "$(dirname "$0")" && pwd)

sudo pacman -S --needed --noconfirm base-devel git cmake meson ninja pkgconf \
    wayland wayland-protocols libxkbcommon pixman libdrm libinput seatd mesa libglvnd \
    libdisplay-info hwdata libliftoff lcms2 vulkan-headers vulkan-icd-loader glslang \
    libxcb xcb-util-wm xcb-util-renderutil xcb-util-errors xorg-xwayland \
    glib2 glib2-devel json-glib gnome-desktop gsettings-desktop-schemas dconf \
    systemd-libs libpipewire libpulse
[[ ${1:-} != --deps ]] || exit 0

mkdir -p "$WORK" && cd "$WORK"
[[ -d anland ]] || git clone https://github.com/SuperTurtleDev/anland.git
git -C anland checkout -q "$ANLAND_REV"
[[ -d phoc ]] || git clone --depth 1 --branch "$PHOC_TAG" https://gitlab.gnome.org/World/Phosh/phoc.git
git -C phoc checkout -q -f "$PHOC_TAG" && git -C phoc clean -qfdx -e subprojects

# The producer library: what a compositor talks to Anland through.
mkdir -p producer
printf 'cmake_minimum_required(VERSION 3.19)\nproject(anland_public LANGUAGES C)\nadd_subdirectory(%s/anland/libdisplay_producer producer)\n' "$WORK" > producer/CMakeLists.txt
cmake -S producer -B build-producer -G Ninja -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX="$PREFIX" -DCMAKE_INSTALL_LIBDIR=lib
cmake --build build-producer
sudo cmake --install build-producer

# Mango's backend goes in unchanged, the patch adds what ties it to phoc.
mkdir -p phoc/src/anland
B=anland/producers/mango/anland_backend
cp "$B"/{anland.c,output.c,buffer.c,input.c,clipboard.c,anland.h,internal.h,text.h} phoc/src/anland/
git -C phoc apply "$HERE/phoc-anland.patch"

# wlroots is built into phoc, with Anland's swapchain patch on top of phoc's own.
cp anland/producers/mango/Arch_v5/wlroots.patch phoc/subprojects/packagefiles/wlroots/9000-anland-external-swapchain.patch
grep -q 9000-anland phoc/subprojects/wlroots.wrap ||
    sed -i 's|^\(  wlroots/0001-.*\)$|\1,\n  wlroots/9000-anland-external-swapchain.patch|' phoc/subprojects/wlroots.wrap
rm -rf phoc/subprojects/wlroots-0.20.x

rm -rf build-phoc
PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig" meson setup build-phoc phoc \
    --prefix="$PREFIX" --buildtype=release -Danland=enabled -Dembed-wlroots=enabled \
    -Dtests=false -Dman=false -Dgtk_doc=false \
    -Dc_link_args="-Wl,-rpath,$PREFIX/lib"
meson compile -C build-phoc
sudo meson install -C build-phoc --no-rebuild
echo "installed: $PREFIX/bin/phoc"
