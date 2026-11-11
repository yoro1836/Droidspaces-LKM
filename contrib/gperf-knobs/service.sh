#!/system/bin/sh
# Put the scheduler into game mode while a listed app has focus. Entering game
# mode is what starts the vendor frame governor (and makes it re-read knob.txt).
MODDIR=${0%/*}
. "$MODDIR/common.sh"
[ "$(getprop ro.hardware)" = s5e9945 ] || exit 0
MODE=/sys/devices/platform/ems/emstune/req_mode
[ -w "$MODE" ] || exit 0
GAME_MODE=3
ours=0

focused_package() {
	# "  mCurrentFocus=Window{1a2b3c u0 com.example.game/com.example.Main}"
	dumpsys window 2>/dev/null | grep -m1 mCurrentFocus | sed -n 's/.* \([^ /]*\)\/[^ ]*}.*/\1/p'
}

until [ "$(getprop sys.boot_completed)" = 1 ]; do sleep 5; done
while :; do
	sleep 3
	[ -s "$GAMES" ] || continue
	pkg=$(focused_package)
	if [ -n "$pkg" ] && grep -qxF "$pkg" "$GAMES"; then
		# Re-assert each round: other writers of req_mode simply overwrite it.
		[ "$(cat $MODE)" = "$GAME_MODE" ] || echo $GAME_MODE > $MODE
		ours=1
	elif [ "$ours" = 1 ]; then
		[ "$(cat $MODE)" = "$GAME_MODE" ] && echo 0 > $MODE
		ours=0
	fi
done
