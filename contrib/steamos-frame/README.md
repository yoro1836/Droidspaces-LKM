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

## Game controllers without Hardware Access

Hardware Access gives the container the phone's whole `/dev` and a writable
`/sys`: touchscreen, sensors, disks, everything. Hiding the dangerous parts
again afterwards is not reliable, because device nodes in the kernel devtmpfs
are flat files that keep appearing. The script goes the other way: Hardware
Access stays off, and a udev rule (`71-droidspaces-gamepad.rules`) creates a
node in the container's isolated `/dev` only for USB or Bluetooth game
controllers, when they are connected. Event numbers that change between
connections are handled by the rule, and
`droidspaces-gamepad-scan.service` picks up controllers that were connected
before the container started. Nothing else of the phone becomes visible.

`/etc/droidspaces-prep/devnode scan` runs the same scan by hand.

```sh
# inside the container, as root
./droidspaces-prep.sh
# or on an extracted tree, before packing the tarball
./droidspaces-prep.sh /path/to/rootfs
# remove everything the script created
./droidspaces-prep.sh --undo [ROOT]
```

SteamOS mounts an overlay on `/etc` at boot (`etc.mount`), and systemd reads
its unit files before that mount exists. A mask written through the overlay is
therefore not seen at the next boot. When the script finds the overlay it folds
the overlay's contents into the real `/etc`, works there, and masks `etc.mount`.

Restart the container afterwards. What was created is listed in
`/etc/droidspaces-prep.manifest`.

Left running on purpose: NetworkManager, systemd-resolved, systemd-udevd (with
the vendor rules masked), upower, avahi, sshd.

Checked against `steamframe-oobe-repair-20260922.5153644-0.3.0`: every unit and
rule name in the script exists in that image, and apply, re-apply and `--undo`
round-trip to an identical `/etc`. The controller rule has not been tried with
a real controller yet.

## Steam UI rendering under gamescope

Notes from getting the Steam client UI (CEF, Chromium 126) GPU-rendered at the
panel rate on a Galaxy S24 (Exynos 2400, RADV-Xclipse) with gamescope 3.16.28
and the Anland backend. `cef-trace.py` is the tool that found each of these: it
records a Chromium trace through the web helper's DevTools port (8080) and
prints the GPU feature status, the `requestAnimationFrame` rate of each page
and where every thread spends its frame.

- Start Steam with `-cef-use-vulkan`. Passing only `--use-angle=vulkan` to the
  web helper looks fine but is software rendering at about 20 fps: Chromium
  wants an EGL config for the 32-bit visual it uses when a compositing manager
  is present (gamescope is one), ANGLE's Vulkan backend only offers the root
  visual, `eglCreateWindowSurface` fails with `EGL_BAD_CONFIG`, and Chromium
  falls back to software compositing without saying so. `-cef-use-vulkan` also
  enables the `Vulkan`, `DefaultANGLEVulkan` and `VulkanFromANGLE` features, so
  the compositor presents through a Vulkan swapchain and never needs that
  config.
- Set `DISABLE_GAMESCOPE_WSI=1` for the web helper only (in
  `steamwebhelper.sh`). The gamescope WSI layer lets the main view bypass
  Xwayland, which replaces the whole toplevel with that one buffer; the Steam
  menu, quick access and toasts are sibling child windows of the same toplevel
  and disappear. The layer also answers a resize with
  `VK_ERROR_OUT_OF_DATE_KHR` on present, which Chromium 126 treats as fatal:
  the GPU process exits, and after three exits Chromium is back on software
  rendering. Games are started by Steam, not by the web helper, and keep the
  layer.
- Give gamescope the panel rate (`-r 120`). The Anland backend starts before
  the Android side connects and comes up at 60 Hz; the Xwayland output keeps
  that mode, so Steam renders at 60 on a 120 Hz panel.

```sh
# with Steam running; switch to it and scroll while it records
CEF_SECS=6 python3 cef-trace.py
```

Healthy output has `"gpu_compositing": "enabled"`, `"vulkan": "enabled_on"`, a
`gap_med` near the frame time for the Big Picture page, and no
`SoftwareRenderer` rows.
