#!/system/bin/sh
MODDIR=${0%/*}
. "$MODDIR/common.sh"
cur=$(current_profile)
next=
take=0
for p in $PROFILES; do
	[ "$take" = 1 ] && { next=$p; break; }
	[ "$p" = "$cur" ] && take=1
done
[ -n "$next" ] || next=stock
echo "$next" > "$STATE"
if apply_profile "$next"; then
	echo "gperf profile: $cur -> $next"
	echo "Applies the next time a game starts."
else
	echo "failed to write $KNOB_FILE"
fi
