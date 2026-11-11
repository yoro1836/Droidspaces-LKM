# Shared by the module scripts. gperf re-reads the knob file each time the
# kernel enters game mode, so a profile change applies at the next game start.
MODDIR=${MODDIR:-${0%/*}}
KNOB_DIR=${KNOB_DIR:-/data/vendor/exynos-profiler}
KNOB_FILE=$KNOB_DIR/knob.txt
STATE=${STATE:-/data/adb/gperf-knobs.profile}
GAMES=${GAMES:-/data/adb/gperf-knobs.games}
PROFILES="stock performance balanced cool"

current_profile() {
	p=$(cat "$STATE" 2>/dev/null)
	[ -f "$MODDIR/profiles/$p.knob" ] || p=stock
	echo "$p"
}

apply_profile() {
	p=$1
	if [ "$p" = stock ]; then
		rm -f "$KNOB_FILE"
		return 0
	fi
	mkdir -p "$KNOB_DIR" || return 1
	# The daemon splits on whitespace and has no comment syntax: strip comments
	# and blank lines so only name=value tokens reach it.
	sed -e 's/#.*//' -e '/^[[:space:]]*$/d' "$MODDIR/profiles/$p.knob" > "$KNOB_FILE.tmp" || return 1
	mv "$KNOB_FILE.tmp" "$KNOB_FILE"
	chown root:root "$KNOB_DIR" "$KNOB_FILE"
	chmod 755 "$KNOB_DIR"
	chmod 644 "$KNOB_FILE"
	chcon --reference=/data/vendor "$KNOB_DIR" "$KNOB_FILE" 2>/dev/null
	return 0
}
