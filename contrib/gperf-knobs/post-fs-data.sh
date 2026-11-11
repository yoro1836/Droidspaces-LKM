#!/system/bin/sh
MODDIR=${0%/*}
. "$MODDIR/common.sh"
[ "$(getprop ro.hardware)" = s5e9945 ] || exit 0
apply_profile "$(current_profile)"
