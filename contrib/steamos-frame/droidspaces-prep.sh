#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Prepare a Steam Frame SteamOS root filesystem (deckard, ARM64) to run as a
# Droidspaces container on a phone.
#
# SteamOS expects to own the device: it has services and udev rules that
# configure the USB gadget, charger, fan, LEDs, FPGA, boot loader, partitions
# and OS updates. A Droidspaces container is privileged and still receives the
# phone's hardware uevents, so those must not run. This script only creates
# mask symlinks (-> /dev/null) under /etc and empties /etc/fstab; nothing under
# /usr is changed, and --undo removes exactly what it created.
#
# Usage:
#   droidspaces-prep.sh [--undo] [ROOT]
# ROOT is the root filesystem directory (default "/": run inside the container,
# as root). It can also be an extracted tree before it is packed into a tarball.
set -euo pipefail

undo=0
if [[ "${1:-}" == --undo ]]; then undo=1; shift; fi
ROOT="${1:-/}"
ROOT="${ROOT%/}"
[[ -d "$ROOT/etc/systemd" && -d "$ROOT/usr/lib/systemd" ]] || { echo "not a systemd root: ${ROOT:-/}" >&2; exit 1; }
grep -qs '^ID=steamos' "$ROOT/etc/os-release" || { echo "not SteamOS: ${ROOT:-/}" >&2; exit 1; }
[[ -w "$ROOT/etc" ]] || { echo "need write access to ${ROOT:-/}/etc (run as root)" >&2; exit 1; }

MANIFEST="$ROOT/etc/droidspaces-prep.manifest"

# System units. Grouped by what they would touch on a real headset.
SYSTEM_UNITS=(
	# USB gadget (configfs), in-container adbd and USB networking
	usb-gadget.target usb-gadget.service usb-gadget-init.service
	adbd.service adbd-pre.service adbd-post.service 'dev-usb\x2dffs-adb.mount'
	usb-ncm-gadget@.service usb-ncm-dnsmasq@.service
	# Headset hardware daemons
	deckard-audio-setup.service deckard-boot-images.service deckard-charger.service
	deckard-fan-control.service deckard-fpga.service deckard-fpga-resume.service
	deckard-led-control.service deckard-power-monitor.service deckard-typec-logger.service
	dsp_service.service gpu-trace.service iris-driver-rebind.service softapmanager.service
	steam-video-codec-setup.service fancontrol.service set-bluetooth-mac-address.service
	steamvr-program-ble.service steamvr-set-kernel-thread-priorities.service
	steamvr-v4l2loopback.service steamvr-web-debug-portforward.service
	# Boot loader, partitions, OS update and device management
	setubootenv.service steamos-boot.service steamos-post-update.service
	steamos-finish-oobe-migration.service steamos-initrd-log-import.service
	holo-post-update-shutdown.service steamos-offload.target atomupd.service rauc.service
	steamos-manager.service steamos-cfs-debugfs-tunings.service steamos-devkit-service.service
	steamos-dump-info.service steamos-log-submitter.service
	mkinitcpio-generate-shutdown-ramfs.service systemd-boot-update.service
	systemd-repart.service systemd-pstore.service
	# Kernel interfaces that are global, not per container
	sys-kernel-config.mount sys-kernel-debug.mount sys-kernel-tracing.mount
	systemd-modules-load.service systemd-backlight@.service
	systemd-rfkill.service systemd-rfkill.socket
	# Radios, disks and the display manager (no such hardware in the container)
	bluetooth.service iwd.service wpa_supplicant.service udisks2.service firewalld.service
	sddm.service
)

# User units: the stock VR/gamescope session must never start by itself.
USER_UNITS=(
	steamvr.service steamvr-logs.service steamvr-nested-desktop.service
	steamvr-proxmicmute.service steamvr-v4l2cam.service steamos-powerbuttond.service
	steamos-manager.service steamos-manager-configure-cecd.service
	steamos-manager-session-cleanup.service steamos-scheduler.service
	gamescope-session.service steam.service
)

# udev rules that run programs or change device attributes for headset hardware.
UDEV_RULES=(
	typec-plug-event 70-steamos-power-button 79-steamos-log-submitter 90-iocost
	90-mac-addresses 90-steam-inputplumber 99-backlight 99-cdsp-permissions 99-eeprom
	99-exp5-permissions 99-gpiod-permissions 99-gpu-permissions 99-hwmon-max34417
	99-leds 99-rgb-cam-permissions 99-sdcard-rescan 99-spidev-permissions
	99-steamos-automount 99-steamvr
)

if (( undo )); then
	[[ -f "$MANIFEST" ]] || { echo "nothing to undo (no $MANIFEST)" >&2; exit 1; }
	while IFS= read -r rel; do
		p="$ROOT/$rel"
		if [[ -L "$p" && "$(readlink "$p")" == /dev/null ]]; then rm -f -- "$p"; fi
		if [[ -e "$p.steamos-orig" || -L "$p.steamos-orig" ]]; then mv -f -- "$p.steamos-orig" "$p"; fi
	done < "$MANIFEST"
	if [[ -f "$ROOT/etc/fstab.steamos-orig" ]]; then mv -f "$ROOT/etc/fstab.steamos-orig" "$ROOT/etc/fstab"; fi
	rm -f "$MANIFEST"
	echo "undone. Restart the container."
	exit 0
fi

masked=0 kept=0
mask() { # mask DIR NAME
	local rel="$1/$2" p="$ROOT/$1/$2"
	if [[ -L "$p" && "$(readlink "$p")" == /dev/null ]]; then
		grep -qxF -- "$rel" "$MANIFEST" 2>/dev/null || kept=$((kept + 1))
		return 0
	fi
	# An enable symlink or a local override would shadow the mask: keep a note, replace it.
	if [[ -e "$p" || -L "$p" ]]; then mv -f -- "$p" "$p.steamos-orig"; fi
	ln -s /dev/null "$p"
	printf '%s\n' "$rel" >> "$MANIFEST"
	masked=$((masked + 1))
}

mkdir -p "$ROOT/etc/systemd/system" "$ROOT/etc/systemd/user" "$ROOT/etc/udev/rules.d"
touch "$MANIFEST"
for u in "${SYSTEM_UNITS[@]}"; do mask etc/systemd/system "$u"; done
for u in "${USER_UNITS[@]}"; do mask etc/systemd/user "$u"; done
for r in "${UDEV_RULES[@]}"; do mask etc/udev/rules.d "$r.rules"; done

# /etc/fstab names the headset's partitions (A/B efi, esp, home, persist).
if [[ ! -f "$ROOT/etc/fstab.steamos-orig" ]] && grep -qsE '^[^#[:space:]]' "$ROOT/etc/fstab"; then
	cp -p "$ROOT/etc/fstab" "$ROOT/etc/fstab.steamos-orig"
	printf '# Emptied by droidspaces-prep.sh: the container has none of the headset partitions.\n' > "$ROOT/etc/fstab"
fi

echo "masked $masked new item(s); $kept were already masked by something else."
echo "manifest: ${MANIFEST}"
if [[ -z "$ROOT" ]]; then
	echo "Restart the container for this to take effect."
fi
