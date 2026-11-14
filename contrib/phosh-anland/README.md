# Phosh on Anland

Phosh, the GNOME phone shell, drawn on an Android surface through
[Anland](https://github.com/SuperTurtleDev/anland), for an Arch Linux container
on a phone.

Anland has no recipe for Phosh. It has one for mango, which like Phosh's
compositor phoc is built on wlroots, and phoc 0.57 uses the same wlroots
release (0.20) that recipe pins. So this takes mango's Anland backend as it
is and gives phoc the little it needs to use it:

- `build.sh` builds Anland's producer library and phoc 0.57.0 with wlroots
  built in, carrying Anland's external-swapchain patch, and installs both
  under `/usr/lib/phoc-anland`. The distribution's phoc is left alone.
- `phoc-anland.patch` makes phoc create the Anland backend when
  `ANLAND_SOCKET` is set, draw into the swapchain Android hands out, and
  stand in for the four things the backend reads from mango's global state.
- `phosh-anland` starts the session.

```sh
sudo pacman -S phosh          # the shell itself, from the distribution
./build.sh
./phosh-anland
```

The container needs GPU access and Anland Display turned on in Droidspaces,
which gives it `/run/display.sock` and `/dev/dri/renderD128`.

Text committed by the Android keyboard is dropped: that path goes through
mango's own input-method relay. Phosh's on-screen keyboard and physical keys
work as usual.

Compiled and started as far as the Anland handshake on x86_64 Arch. Not yet
seen on a screen.
