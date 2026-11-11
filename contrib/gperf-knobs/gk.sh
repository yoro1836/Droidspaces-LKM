#!/system/bin/sh
# Backend for the WebUI: gk.sh status | profile <name> | games | toggle <pkg> | log | clearlog
MODDIR=${0%/*}
. "$MODDIR/common.sh"
case "$1" in
status)
	echo "profile=$(current_profile)"
	echo "mode=$(cat $MODE 2>/dev/null | head -1)"
	echo "governor=$(cat $PROF/profiler/running 2>/dev/null)"
	echo "knob=$([ -f "$KNOB_FILE" ] && stat -c %x "$KNOB_FILE" | cut -c1-19)"
	echo "service=$(pgrep -f "$MODDIR/service.sh" >/dev/null && echo 1 || echo 0)"
	echo "sample=$(sample)"
	;;
profile) set_profile "$2" && echo ok ;;
games)
	# "<1|0> <package>" for every third-party package, listed ones first.
	touch "$GAMES"
	pm list packages -3 2>/dev/null | sed 's/^package://' | sort | while read -r p; do
		grep -qxF "$p" "$GAMES" && echo "1 $p" || echo "0 $p"
	done | sort -r -s -k1,1
	;;
toggle)
	[ -n "$2" ] || exit 1
	touch "$GAMES"
	if grep -qxF "$2" "$GAMES"; then
		grep -vxF "$2" "$GAMES" > "$GAMES.tmp"; mv "$GAMES.tmp" "$GAMES"; log "list - $2"
	else
		echo "$2" >> "$GAMES"; log "list + $2"
	fi
	echo ok ;;
log) tail -n "${2:-200}" "$LOG" 2>/dev/null ;;
clearlog) : > "$LOG"; echo ok ;;
*) exit 1 ;;
esac
