#!/system/bin/sh
# SPDX-License-Identifier: GPL-2.0-only
# MODDIR is supplied by the entry script (or MODPATH during installation).
DS_BTF=/sys/kernel/btf/vmlinux
DS_KERNEL_NOTES=/sys/kernel/notes
DS_MODULE_SYS=/sys/module/droidspaces_ns
DS_DEV_SYS=/sys/module/droidspaces_devtmpfs
DS_SYS_MODULES=/sys/module
DS_KALLSYMS=/proc/kallsyms
DS_PROC_NS=/proc/self/ns
DS_KSUD=/data/adb/ksud
[ -x "$DS_KSUD" ] || DS_KSUD=/data/adb/ksu/bin/ksud
export KSU_MODULE=droidspaces_lkm

# KernelSU clears --temp configuration at every boot, including for disabled modules.
# The file fallback also covers a missing/older ksud, so failures remain visible.
ds_status() {
    ds_message=$1
    printf '%s\n' "$ds_message"
    printf '%s\n' "$ds_message" > "$MODDIR/status.txt"
    if [ -x "$DS_KSUD" ] && "$DS_KSUD" module config set --temp override.description "$ds_message"; then
        return 0
    fi
    DS_DESCRIPTION="$ds_message" awk '
        !/^description=/ { print }
        END { print "description=" ENVIRON["DS_DESCRIPTION"] }
    ' "$MODDIR/module.prop" > "$MODDIR/module.prop.tmp" &&
        cat "$MODDIR/module.prop.tmp" > "$MODDIR/module.prop"
    rm -f "$MODDIR/module.prop.tmp"
}

# KMI generation comes from the kernel release, not the Android userspace version.
ds_target_supported() {
    DS_REASON='仅支持 ARM64 GKI。'
    [ "$(uname -m)" = aarch64 ] || return 1
    ds_release=$(uname -r)
    ds_family=$(printf '%s\n' "$ds_release" | sed -n 's/^\([0-9][0-9]*\.[0-9][0-9]*\)\.[0-9][0-9]*-android[0-9][0-9]*-.*/\1/p')
    ds_android=$(printf '%s\n' "$ds_release" | sed -n 's/^[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*-\(android[0-9][0-9]*\)-.*/\1/p')
    DS_REASON="无法从内核版本识别 GKI KMI：$ds_release"
    [ -n "$ds_family" ] && [ -n "$ds_android" ] || return 1
    DS_KMI="$ds_android-$ds_family"
    DS_REASON="安装包未包含匹配的 KMI：$DS_KMI"
    [ -r "$MODDIR/kernel/manifest.tsv" ] || { DS_REASON='缺少 KMI 清单。'; return 1; }
    ds_row=$(awk -F '|' -v kmi="$DS_KMI" '$1 == kmi { row=$0; count++ } END { if (count==1) print row; else exit 1 }' "$MODDIR/kernel/manifest.tsv") || return 1
    IFS='|' read -r ds_selected DS_PAYLOAD DS_ABI DS_NOTES ds_extra <<MANIFEST
$ds_row
MANIFEST
    DS_REASON='KMI 清单格式无效。'
    [ "$ds_selected" = "$DS_KMI" ] && [ -z "$ds_extra" ] || return 1
    for ds_name in "$DS_PAYLOAD" "$DS_ABI"; do
        case "$ds_name" in ''|.*|*[!a-zA-Z0-9._-]*) return 1;; esac
    done
    case "$DS_NOTES" in .*|*[!a-zA-Z0-9._-]*) return 1;; esac
    DS_REASON=''
    return 0
}

ds_active() {
    [ "$(cat "$DS_MODULE_SYS/parameters/activate" 2>/dev/null)" = Y ] &&
    [ -e "$DS_PROC_NS/pid" ] && [ -e "$DS_PROC_NS/pid_for_children" ] &&
    [ -e "$DS_PROC_NS/ipc" ]
}

ds_payload_valid() {
    [ -s "$MODDIR/kernel/$DS_PAYLOAD" ] &&
    [ -s "$MODDIR/kernel/$DS_ABI" ] &&
    [ -x "$MODDIR/bin/abi-check" ] &&
    { [ -z "$DS_NOTES" ] || [ -s "$MODDIR/kernel/$DS_NOTES" ]; } &&
    (cd "$MODDIR/kernel" && sha256sum -c SHA256SUMS)
}

ds_dev_active() {
    [ "$(cat "$DS_DEV_SYS/parameters/ready" 2>/dev/null)" = Y ] &&
    [ "$(cat "$DS_DEV_SYS/parameters/errors" 2>/dev/null)" = 0 ]
}

# Optional devtmpfs payload: kernel/devtmpfs.tsv rows "kmi|module.ko|symbols".
# Vendor-header builds (Samsung KDP) leave non-KMI symbols unversioned for ksud
# to resolve from kallsyms; every listed symbol must exist before loading.
ds_devtmpfs_entry() {
    DS_DEV_PAYLOAD=''
    DS_DEV_SYMS=''
    [ -r "$MODDIR/kernel/devtmpfs.tsv" ] || return 1
    ds_dev_row=$(awk -F '|' -v kmi="$DS_KMI" '$1 == kmi { row=$0; count++ } END { if (count==1) print row; else exit 1 }' "$MODDIR/kernel/devtmpfs.tsv") || return 1
    IFS='|' read -r ds_dev_kmi DS_DEV_PAYLOAD DS_DEV_SYMS ds_dev_extra <<DEVTMPFS
$ds_dev_row
DEVTMPFS
    [ "$ds_dev_kmi" = "$DS_KMI" ] && [ -z "$ds_dev_extra" ] || return 1
    for ds_name in "$DS_DEV_PAYLOAD" "$DS_DEV_SYMS"; do
        case "$ds_name" in ''|.*|*[!a-zA-Z0-9._-]*) return 1;; esac
    done
    [ -s "$MODDIR/kernel/$DS_DEV_PAYLOAD" ] && [ -s "$MODDIR/kernel/$DS_DEV_SYMS" ]
}

# One pass over kallsyms; three-field lines are vmlinux (module lines add [name]).
# Usage: ds_symbols_present <symbol list file> <label>
ds_symbols_present() {
    awk -v label="$2" 'NR == FNR { if ($0 != "") want[$0] = 1; next }
         NF == 3 && ($3 in want) { delete want[$3] }
         END {
             for (s in want) missing = missing " " s
             if (missing != "") { print label ": missing kernel symbols:" missing; exit 1 }
         }' "$1" "$DS_KALLSYMS"
}

ds_devtmpfs_symbols_present() {
    ds_symbols_present "$MODDIR/kernel/$DS_DEV_SYMS" devtmpfs
}

# Vendor-header payloads leave non-KMI symbols to kallsyms; when the package
# ships <payload>.syms, every listed symbol must exist before loading.
ds_payload_symbols_present() {
    [ -s "$MODDIR/kernel/$DS_PAYLOAD.syms" ] || return 0
    ds_symbols_present "$MODDIR/kernel/$DS_PAYLOAD.syms" droidspaces_ns
}

# "PID / IPC", plus "/ user" when the payload provides user namespaces.
ds_ns_label() {
    DS_NS_LABEL='PID / IPC'
    [ -e "$DS_PROC_NS/user" ] && DS_NS_LABEL='PID / IPC / user'
}

# Runs once PID / IPC is active. Sets DS_DEV_NOTE for the final status;
# a devtmpfs problem never undoes the namespace result.
ds_devtmpfs_load() {
    DS_DEV_NOTE=''
    ds_devtmpfs_entry || return 0
    if ds_dev_active; then
        DS_DEV_NOTE=' 与 devtmpfs'
        return 0
    fi
    if [ -d "$DS_DEV_SYS" ]; then
        DS_DEV_NOTE='；devtmpfs 已存在但 ready/errors 检查未通过，请重启'
        return 1
    fi
    if ! ds_devtmpfs_symbols_present; then
        DS_DEV_NOTE='；devtmpfs 所需内核符号缺失，未加载（详见 load.log）'
        return 1
    fi
    "$DS_KSUD" insmod "$MODDIR/kernel/$DS_DEV_PAYLOAD" gki=1
    ds_result=$?
    if [ "$ds_result" -ne 0 ] || ! ds_dev_active; then
        DS_DEV_NOTE="；devtmpfs 返回 ${ds_result} 或 ready/errors 检查未通过（详见 load.log）"
        return 1
    fi
    DS_DEV_NOTE=' 与 devtmpfs'
}

# Optional extra modules: kernel/extras.tsv rows "kmi|module.ko", loaded in
# file order after the namespace module (netfilter matches, nftables, ...).
# A row's <module.ko>.syms, when shipped, must be satisfied by kallsyms first.
# Sets DS_EXTRA_NOTE; a failure never undoes the namespace result.
ds_extras_load() {
    DS_EXTRA_NOTE=''
    [ -r "$MODDIR/kernel/extras.tsv" ] || return 0
    ds_extra_ok=0
    ds_extra_bad=''
    while IFS='|' read -r ds_extra_kmi ds_extra_ko ds_extra_rest; do
        [ "$ds_extra_kmi" = "$DS_KMI" ] || continue
        case "$ds_extra_ko" in ''|.*|*[!a-zA-Z0-9._-]*) ds_extra_bad="$ds_extra_bad ?"; continue;; esac
        if [ -n "$ds_extra_rest" ] || [ ! -s "$MODDIR/kernel/$ds_extra_ko" ]; then
            ds_extra_bad="$ds_extra_bad $ds_extra_ko"
            continue
        fi
        ds_extra_name=$(printf '%s\n' "${ds_extra_ko%.ko}" | tr - _)
        if [ -d "$DS_SYS_MODULES/$ds_extra_name" ]; then
            ds_extra_ok=$((ds_extra_ok + 1))
            continue
        fi
        if [ -s "$MODDIR/kernel/$ds_extra_ko.syms" ] &&
            ! ds_symbols_present "$MODDIR/kernel/$ds_extra_ko.syms" "$ds_extra_name"; then
            ds_extra_bad="$ds_extra_bad $ds_extra_name"
            continue
        fi
        if "$DS_KSUD" insmod "$MODDIR/kernel/$ds_extra_ko" && [ -d "$DS_SYS_MODULES/$ds_extra_name" ]; then
            ds_extra_ok=$((ds_extra_ok + 1))
        else
            ds_extra_bad="$ds_extra_bad $ds_extra_name"
        fi
    done < "$MODDIR/kernel/extras.tsv"
    if [ -n "$ds_extra_bad" ]; then
        DS_EXTRA_NOTE="；扩展模块未加载：${ds_extra_bad# }（详见 load.log）"
        return 1
    fi
    [ "$ds_extra_ok" -eq 0 ] || DS_EXTRA_NOTE=" 及 ${ds_extra_ok} 个扩展模块"
}

# devtmpfs, then the extras. Both run even if the first fails.
ds_optional_load() {
    ds_optional_result=0
    ds_devtmpfs_load || ds_optional_result=1
    ds_extras_load || ds_optional_result=1
    DS_DEV_NOTE="$DS_DEV_NOTE$DS_EXTRA_NOTE"
    return "$ds_optional_result"
}

# KMI is a routing key; internal namespace hooks also require matching host ABI.
ds_abi_compatible() {
    if [ -r "$DS_BTF" ]; then
        "$MODDIR/bin/abi-check" "$MODDIR/kernel/$DS_ABI" "$DS_BTF"
        return $?
    fi
    # Old GKI builds may omit BTF. Only the exact validated build is accepted.
    if [ -n "$DS_NOTES" ] && [ -r "$DS_KERNEL_NOTES" ] &&
        cmp -s "$DS_KERNEL_NOTES" "$MODDIR/kernel/$DS_NOTES"; then
        printf 'Kernel BTF unavailable; exact validated kernel notes matched.\n'
        return 0
    fi
    printf 'Kernel BTF unavailable and validated kernel notes do not match.\n'
    return 1
}

ds_load() {
    if ! ds_target_supported; then
        ds_status "[不支持] ${DS_REASON}；未加载。"
        return 1
    fi
    if ds_active; then
        ds_ns_label
        if ds_optional_load; then
            ds_status "[已加载] ${DS_KMI}：${DS_NS_LABEL} namespace${DS_DEV_NOTE} 已激活（本次开机已加载）；更换 .ko 需重启。"
        else
            ds_status "[部分加载] ${DS_KMI}：${DS_NS_LABEL} namespace 已激活${DS_DEV_NOTE}。"
        fi
        return 0
    fi
    if [ -d "$DS_MODULE_SYS" ]; then
        ds_status '[加载失败] droidspaces_ns 已存在但未激活，或 namespace 接口不完整；请重启后重试。'
        return 1
    fi
    if [ ! -x "$DS_KSUD" ]; then
        ds_status '[加载失败] 找不到可执行的 ksud；请检查 KernelSU，日志见模块目录 load.log。'
        return 1
    fi
    if ! ds_payload_valid; then
        ds_status '[加载失败] .ko 缺失或 SHA-256 校验失败；请重新安装完整模块 ZIP。'
        return 1
    fi
    if ! ds_abi_compatible; then
        ds_status "[不兼容] ${DS_KMI}：内核 ABI 或构建指纹校验失败，未加载；详见 load.log。"
        return 1
    fi
    if ! ds_payload_symbols_present; then
        ds_status "[不兼容] ${DS_KMI}：droidspaces_ns 所需内核符号缺失，未加载；详见 load.log。"
        return 1
    fi
    ds_status "[加载中] ${DS_KMI}：正在激活 PID / IPC namespace。"
    "$DS_KSUD" insmod "$MODDIR/kernel/$DS_PAYLOAD" gki=1 activate=1
    ds_result=$?
    if [ "$ds_result" -ne 0 ]; then
        ds_status "[加载失败] ksud insmod 返回 ${ds_result}；详见模块目录 load.log。"
        return 1
    fi
    if ! ds_active; then
        ds_status '[加载失败] insmod 已返回成功，但 activate 或 PID / IPC namespace 检查未通过；详见 load.log。'
        return 1
    fi
    ds_ns_label
    if ! ds_optional_load; then
        ds_status "[部分加载] ${DS_KMI}：${DS_NS_LABEL} namespace 已激活${DS_DEV_NOTE}。"
        return 0
    fi
    ds_status "[已加载] ${DS_KMI}：${DS_NS_LABEL} namespace${DS_DEV_NOTE} 已激活；更换 .ko 需重启。"
}
