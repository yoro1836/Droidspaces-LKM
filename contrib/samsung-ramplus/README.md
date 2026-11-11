# RAM Plus for container processes (Samsung)

Samsung kernels built with `CONFIG_ZRAM_RAMPLUS` can move zram contents out to
a file on flash, which is what the "RAM Plus" setting provides. On the S24
(S5E9945, 6.1) this is done per process: the Android framework swaps an app
out with `process_madvise(MADV_PAGEOUT)` and then asks zram to write those
swap slots to the backing device with the vendor-specific `MADV_WRITEBACK`
(29; `MADV_PREFETCH`, 30, reads them back). `drivers/block/zram/zram_drv.c`
and `mm/madvise.c` in the vendor tree show the path; the generic
`echo idle > /sys/block/zram0/writeback` does nothing useful there.

The framework only does this for Android apps. A container's processes are
invisible to it, so whatever they have in swap stays in RAM as compressed
zram data, and under pressure Android can only make room by killing its own
apps, up to the one showing the container's display.

`ramplus-push` makes the same two calls for the PIDs it is given:

```sh
# on the host, as root; e.g. the Steam client UI while a game is running
ramplus-push $(pgrep steamwebhelper)
ramplus-push -p PID...   # page out to zram only
ramplus-push -w PID...   # write back what is already in zram
ramplus-push -r PID...   # prefetch: read it back in
```

It prints RSS and swap of each process before and after, and the change in
`MemAvailable`, zram's RAM use and the amount on flash.

Memory written to flash is read back on demand when the process touches it,
which is slower than zram, and every write-back is a write to flash. Use it
for processes that are idle while something else needs the RAM, not in a loop.

Build: `gcc -static -O2 ramplus-push.c -o ramplus-push` for arm64.

Checked so far only as far as a generic 6.1 kernel allows (the calls are
made and the missing `MADV_WRITEBACK` is reported); not run on a device yet.
