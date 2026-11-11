# Shared by the module scripts. gperf re-reads the knob file each time the
# kernel enters game mode, so a profile change applies at the next game start.
MODDIR=${MODDIR:-${0%/*}}
KNOB_DIR=${KNOB_DIR:-/data/vendor/exynos-profiler}
KNOB_FILE=$KNOB_DIR/knob.txt
STATE=${STATE:-/data/adb/gperf-knobs.profile}
GAMES=${GAMES:-/data/adb/gperf-knobs.games}
LOG=${LOG:-/data/adb/gperf-knobs.log}
LOG_MAX=262144
PROFILES="stock performance balanced cool"
MODE=/sys/devices/platform/ems/emstune/req_mode
PROF=/sys/devices/platform/exynos-profiler

log() {
	if [ -f "$LOG" ] && [ "$(stat -c %s "$LOG" 2>/dev/null || echo 0)" -gt $LOG_MAX ]; then
		tail -n 400 "$LOG" > "$LOG.tmp" && mv "$LOG.tmp" "$LOG"
	fi
	echo "$(date '+%m-%d %H:%M:%S') $*" >> "$LOG"
}

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

set_profile() {
	[ -f "$MODDIR/profiles/$1.knob" ] || return 1
	echo "$1" > "$STATE"
	apply_profile "$1" && log "profile $1"
}

# One line from the kernel profiler: displayed fps, per-domain frequency (kHz)
# and temperature of CL0 CL1L CL1H CL2 GPU MIF.
sample() {
	awk -F= '
		$1=="profile_time_ms"{t=$2} $1=="profile_frame_cnt"{f=$2}
		$1=="freq"{fr=$2} $1=="temp"{te=$2}
		END{ if (t>0) printf "fps=%d freq=%s temp=%s", f*1000/t, fr, te }
	' "$PROF/control/control_profile" 2>/dev/null
}
