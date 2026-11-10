#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Prepare a Steam Frame SteamOS root filesystem (deckard, ARM64) to run as a
# Droidspaces container on a phone.
#
# SteamOS expects to own the device: it has services and udev rules that
# configure the USB gadget, charger, fan, LEDs, FPGA, boot loader, partitions
# and OS updates. A Droidspaces container is privileged and still receives the
# phone's hardware uevents, so those must not run. This script creates mask
# symlinks (-> /dev/null) under /etc and empties /etc/fstab.
#
# It also installs a game controller allowlist, so controllers work with
# Hardware Access OFF: the container's /dev stays the isolated tmpfs, and a
# udev rule creates a device node only for USB or Bluetooth game controllers
# when they are plugged in. The touchscreen, sensors, disks and every other
# device of the phone stay invisible to the container.
#
# Nothing under /usr is changed, and --undo removes exactly what was created.
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

# SteamOS mounts an overlay on /etc (etc.mount: lower /etc, upper under
# /var/lib/overlays). systemd reads its unit files before that mount exists,
# so a mask written through the overlay lands in the upper layer and is not
# seen at the next boot: the masked services start anyway. Work on the real
# /etc underneath instead, fold the overlay's current contents into it, and
# mask etc.mount so the container boots with one plain /etc from then on.
LOWER=
cleanup() { if [[ -n "$LOWER" ]]; then umount "$LOWER" 2>/dev/null || true; rmdir "$LOWER" 2>/dev/null || true; fi; }
trap cleanup EXIT
if [[ "$(findmnt -n -o FSTYPE -M "${ROOT:-/}${ROOT:+/}etc" 2>/dev/null)" == overlay ]]; then
	merged="$ROOT/etc"
	LOWER="$(mktemp -d)"
	# A non-recursive bind shows the directory under the overlay mount.
	mount --bind "${ROOT:-/}" "$LOWER"
	[[ -d "$LOWER/etc/systemd" ]] || { echo "cannot reach the real /etc under the overlay" >&2; exit 1; }
	if (( ! undo )); then
		echo "/etc is an overlay: folding it into the real /etc."
		cp -a -- "$merged/." "$LOWER/etc/"
		# Entries deleted through the overlay must go from the real /etc too.
		( cd "$LOWER/etc" && find . -mindepth 1 -depth -print0 ) | while IFS= read -r -d '' f; do
			[[ -e "$merged/$f" || -L "$merged/$f" ]] || rm -rf -- "$LOWER/etc/$f"
		done
	fi
	ROOT="$LOWER"
	flattened=1
else
	flattened=0
fi

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
	# SteamOS overlays /etc from /var at boot; see flatten_etc below
	etc.mount
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
		if [[ "$rel" == F:* ]]; then rm -f -- "$ROOT/${rel#F:}"; continue; fi
		p="$ROOT/$rel"
		if [[ -L "$p" && "$(readlink "$p")" == /dev/null ]]; then rm -f -- "$p"; fi
		if [[ -e "$p.steamos-orig" || -L "$p.steamos-orig" ]]; then mv -f -- "$p.steamos-orig" "$p"; fi
	done < "$MANIFEST"
	if [[ -f "$ROOT/etc/fstab.steamos-orig" ]]; then mv -f "$ROOT/etc/fstab.steamos-orig" "$ROOT/etc/fstab"; fi
	rmdir "$ROOT/etc/droidspaces-prep" 2>/dev/null || true
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

# Game controller allowlist.
install_file() { # install_file REL MODE  (content on stdin)
	local rel="$1" p="$ROOT/$1"
	mkdir -p "$(dirname "$p")"
	cat > "$p"
	chmod "$2" "$p"
	grep -qxF -- "F:$rel" "$MANIFEST" || printf 'F:%s\n' "$rel" >> "$MANIFEST"
}

install_file etc/droidspaces-prep/devnode 0755 <<'DEVNODE'
#!/bin/sh
# Create or remove one input device node in the container's isolated /dev.
# Called by 71-droidspaces-gamepad.rules; "scan" picks up controllers that
# were already connected when the container started.
#
# With Hardware Access on, /dev is the kernel devtmpfs: the nodes already exist
# and must not be touched from here.
[ "$(stat -f -c %T /dev 2>/dev/null)" = tmpfs ] || exit 0

node_path() {
	case "$1" in
		event[0-9]*|js[0-9]*) echo "/dev/input/$1" ;;
		hidraw[0-9]*) echo "/dev/$1" ;;
		*) return 1 ;;
	esac
}

case "$1" in
	add)
		p=$(node_path "$2") || exit 1
		case "$3$4" in ''|*[!0-9]*) exit 1 ;; esac
		mkdir -p /dev/input
		[ -e "$p" ] || mknod -m 0660 "$p" c "$3" "$4" || exit 1
		chgrp input "$p" 2>/dev/null
		;;
	remove)
		p=$(node_path "$2") || exit 1
		rm -f "$p"
		;;
	scan)
		for d in /sys/class/input/event* /sys/class/input/js*; do
			[ -e "$d/dev" ] || continue
			# USB (0003) or Bluetooth (0005) only: never the phone's own devices.
			case "$(cat "$d/device/id/bustype" 2>/dev/null)" in 0003|0005) ;; *) continue ;; esac
			udevadm test-builtin input_id "$d" 2>/dev/null | grep -q '^ID_INPUT_JOYSTICK=1' || continue
			IFS=: read -r maj min < "$d/dev"
			"$0" add "${d##*/}" "$maj" "$min"
		done
		;;
	*)
		echo "usage: $0 add NAME MAJOR MINOR | remove NAME | scan" >&2
		exit 1
		;;
esac
DEVNODE

install_file etc/udev/rules.d/71-droidspaces-gamepad.rules 0644 <<'RULES'
# Game controllers for a Droidspaces container with Hardware Access off.
# The container's /dev is an isolated tmpfs, so no device node appears by
# itself. Create one only for USB (bustype 0003) or Bluetooth (0005) game
# controllers; the phone's touchscreen, sensors and keys never match.
ACTION=="add", SUBSYSTEM=="input", KERNEL=="event*|js*", ATTRS{id/bustype}=="0003|0005", ENV{ID_INPUT_JOYSTICK}=="1", ENV{ID_INPUT_TOUCHSCREEN}!="1", ENV{ID_INPUT_ACCELEROMETER}!="1", RUN+="/etc/droidspaces-prep/devnode add %k %M %m"
ACTION=="remove", SUBSYSTEM=="input", KERNEL=="event*|js*", RUN+="/etc/droidspaces-prep/devnode remove %k"
# Raw HID for controllers Steam Input drives itself (gyro, touchpad, rumble):
# Valve 28DE, Sony 054C, Nintendo 057E.
ACTION=="add", SUBSYSTEM=="hidraw", KERNELS=="*:28DE:*|*:054C:*|*:057E:*", RUN+="/etc/droidspaces-prep/devnode add %k %M %m"
ACTION=="remove", SUBSYSTEM=="hidraw", RUN+="/etc/droidspaces-prep/devnode remove %k"
RULES

install_file etc/systemd/system/droidspaces-gamepad-scan.service 0644 <<'UNIT'
[Unit]
Description=Create nodes for game controllers connected before the container started
After=systemd-udevd.service

[Service]
Type=oneshot
ExecStart=/etc/droidspaces-prep/devnode scan

[Install]
WantedBy=multi-user.target
UNIT
mkdir -p "$ROOT/etc/systemd/system/multi-user.target.wants"
if [[ ! -e "$ROOT/etc/systemd/system/multi-user.target.wants/droidspaces-gamepad-scan.service" ]]; then
	ln -s ../droidspaces-gamepad-scan.service "$ROOT/etc/systemd/system/multi-user.target.wants/droidspaces-gamepad-scan.service"
	printf 'F:%s\n' etc/systemd/system/multi-user.target.wants/droidspaces-gamepad-scan.service >> "$MANIFEST"
fi

# /etc/fstab names the headset's partitions (A/B efi, esp, home, persist).
if [[ ! -f "$ROOT/etc/fstab.steamos-orig" ]] && grep -qsE '^[^#[:space:]]' "$ROOT/etc/fstab"; then
	cp -p "$ROOT/etc/fstab" "$ROOT/etc/fstab.steamos-orig"
	printf '# Emptied by droidspaces-prep.sh: the container has none of the headset partitions.\n' > "$ROOT/etc/fstab"
fi

echo "masked $masked new item(s); $kept were already masked by something else."
echo "manifest: /etc/droidspaces-prep.manifest"
if [[ -z "$ROOT" || "$flattened" == 1 ]]; then
	echo "Restart the container for this to take effect."
fi
