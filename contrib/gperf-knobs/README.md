# gperf-knobs

KernelSU module with tuning profiles for `/vendor/bin/gperf`, the userspace half
of Samsung's Exynos frame-based CPU/GPU/MIF governor on S5E9945 (Galaxy S24
Exynos). The daemon reads `/data/vendor/exynos-profiler/knob.txt` every time
the kernel enters game mode; this module only writes that file.

| Profile | What changes |
|---|---|
| stock | no file, vendor defaults |
| balanced | light-load margin cut limited to -200, fps target held longer |
| performance | light-load mode off, no negative margins, higher margin ceilings and memory-bus floor |
| cool | no positive margins, light-load mode entered sooner, thermal safe mode at about 70 C |

The action button in the manager cycles the profile; it applies at the next
game start. `knob.txt` is whitespace-separated `name=value` tokens with integer
values and no comment syntax (the `.knob` files here are stripped before they
are installed). Unknown names are ignored by the daemon.

Status: the file format and the meaning of each knob come from static analysis.
Whether the daemon's SELinux domain may read the file, and what each profile
does to frame rate and temperature, has not been measured on a device.
