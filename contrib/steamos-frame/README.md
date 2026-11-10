# SteamOS (Steam Frame) as a Droidspaces container

`droidspaces-prep.sh` makes a Steam Frame SteamOS root filesystem (deckard,
ARM64) safe to boot as a Droidspaces container on a phone.

SteamOS is built for one device and expects to own it. Its services and udev
rules configure the USB gadget, charger, fan, LEDs, FPGA, boot loader,
partitions and OS updates. A Droidspaces container is privileged and still
receives the phone's hardware uevents even with Hardware Access off, so those
parts have to be disabled before the container is used.

The script masks them with symlinks to `/dev/null` under `/etc` and empties
`/etc/fstab`. Nothing under `/usr` is changed.

```sh
# inside the container, as root
./droidspaces-prep.sh
# or on an extracted tree, before packing the tarball
./droidspaces-prep.sh /path/to/rootfs
# remove everything the script created
./droidspaces-prep.sh --undo [ROOT]
```

Restart the container afterwards. What was created is listed in
`/etc/droidspaces-prep.manifest`.

Left running on purpose: NetworkManager, systemd-resolved, systemd-udevd (with
the vendor rules masked), upower, avahi, sshd.

Checked against `steamframe-oobe-repair-20260922.5153644-0.3.0` (every unit and
rule name in the script exists in that image).
