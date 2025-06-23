#!/usr/bin/env bash
# edge-hardener — Kernel configuration audit module
# Copyright (c) 2026 isecwire GmbH. MIT License.
#
# Sourced by edge_hardener.sh. Expects result_pass/result_fail/result_warn
# functions to be available in the caller's scope.

run_kernel_audit() {
    local kconfig=""
    for cfg in /boot/config-"$(uname -r)" /proc/config.gz; do
        [[ -f "$cfg" ]] && kconfig="$cfg" && break
    done

    local reader="cat"
    if [[ -n "$kconfig" && "$kconfig" == *.gz ]]; then
        reader="zcat"
    fi

    # --- Boot command line checks ---
    local cmdline
    cmdline=$(cat /proc/cmdline 2>/dev/null || echo "")

    # KASLR
    if echo "$cmdline" | grep -q "nokaslr"; then
        result_fail "KASLR disabled via boot params" "nokaslr in /proc/cmdline" \
            "Remove nokaslr from kernel command line"
    else
        result_pass "KASLR not explicitly disabled"
    fi

    # --- CPU feature checks ---
    local cpuinfo
    cpuinfo=$(cat /proc/cpuinfo 2>/dev/null || echo "")

    if echo "$cpuinfo" | grep -q "smep"; then
        result_pass "SMEP supported"
    else
        result_warn "SMEP not detected" "Supervisor Mode Execution Prevention unavailable"
    fi

    if echo "$cpuinfo" | grep -q "smap"; then
        result_pass "SMAP supported"
    else
        result_warn "SMAP not detected" "Supervisor Mode Access Prevention unavailable"
    fi

    # NX/XD bit
    if echo "$cpuinfo" | grep -q "nx"; then
        result_pass "NX (No-Execute) bit supported"
    else
        result_warn "NX bit not detected" "Hardware DEP unavailable"
    fi

    # --- Kernel config checks ---
    if [[ -z "$kconfig" ]]; then
        result_warn "Kernel config not found" \
            "Cannot audit compile-time options (/boot/config-* and /proc/config.gz missing)"
        return
    fi

    result_pass "Kernel config found" "$kconfig"

    # Helper to check a kernel config option
    _kcheck() {
        local option="$1" desired="$2" description="$3" remediation="$4"
        local value
        value=$($reader "$kconfig" 2>/dev/null | grep "^${option}=" | head -1 || true)

        if [[ -z "$value" ]]; then
            # Check if it's explicitly not set
            if $reader "$kconfig" 2>/dev/null | grep -q "# ${option} is not set"; then
                result_fail "$description" "${option} is not set" "$remediation"
            else
                result_warn "$description" "${option} not found in config" "$remediation"
            fi
        elif echo "$value" | grep -q "=${desired}"; then
            result_pass "$description" "$value"
        else
            result_fail "$description" "$value (expected ${desired})" "$remediation"
        fi
    }

    # Stack protector
    _kcheck "CONFIG_STACKPROTECTOR_STRONG" "y" \
        "Stack protector (strong)" \
        "Rebuild kernel with CONFIG_STACKPROTECTOR_STRONG=y"

    # FORTIFY_SOURCE
    _kcheck "CONFIG_FORTIFY_SOURCE" "y" \
        "FORTIFY_SOURCE (buffer overflow detection)" \
        "Rebuild kernel with CONFIG_FORTIFY_SOURCE=y"

    # Hardened usercopy
    _kcheck "CONFIG_HARDENED_USERCOPY" "y" \
        "Hardened usercopy" \
        "Rebuild kernel with CONFIG_HARDENED_USERCOPY=y"

    # VMAP stack (guard pages for kernel stacks)
    _kcheck "CONFIG_VMAP_STACK" "y" \
        "VMAP stack (kernel stack guard pages)" \
        "Rebuild kernel with CONFIG_VMAP_STACK=y"

    # Restrict /dev/mem access
    _kcheck "CONFIG_STRICT_DEVMEM" "y" \
        "Strict /dev/mem access" \
        "Rebuild kernel with CONFIG_STRICT_DEVMEM=y"

    # Restrict kernel memory access via /dev/kmem
    _kcheck "CONFIG_DEVKMEM" "n" \
        "/dev/kmem disabled" \
        "Rebuild kernel with CONFIG_DEVKMEM=n (or unset)"

    # Kernel address display restriction
    local kptr
    kptr=$(cat /proc/sys/kernel/kptr_restrict 2>/dev/null || echo "unknown")
    if [[ "$kptr" == "1" ]] || [[ "$kptr" == "2" ]]; then
        result_pass "kptr_restrict" "kptr_restrict=${kptr}"
    else
        result_warn "kptr_restrict not set" "kptr_restrict=${kptr}" \
            "Set kernel.kptr_restrict=1 (or 2) in /etc/sysctl.d/"
    fi

    # dmesg restrict
    local dmesg_restrict
    dmesg_restrict=$(cat /proc/sys/kernel/dmesg_restrict 2>/dev/null || echo "unknown")
    if [[ "$dmesg_restrict" == "1" ]]; then
        result_pass "dmesg_restrict" "dmesg_restrict=1"
    else
        result_warn "dmesg accessible to unprivileged users" "dmesg_restrict=${dmesg_restrict}" \
            "Set kernel.dmesg_restrict=1 in /etc/sysctl.d/"
    fi

    # Unprivileged BPF
    local unprivileged_bpf
    unprivileged_bpf=$(cat /proc/sys/kernel/unprivileged_bpf_disabled 2>/dev/null || echo "unknown")
    if [[ "$unprivileged_bpf" == "1" ]] || [[ "$unprivileged_bpf" == "2" ]]; then
        result_pass "Unprivileged BPF disabled" "unprivileged_bpf_disabled=${unprivileged_bpf}"
    else
        result_warn "Unprivileged BPF allowed" "unprivileged_bpf_disabled=${unprivileged_bpf}" \
            "Set kernel.unprivileged_bpf_disabled=1 in /etc/sysctl.d/"
    fi

    # User namespaces (commonly exploited)
    local userns
    userns=$(cat /proc/sys/user/max_user_namespaces 2>/dev/null || echo "unknown")
    if [[ "$userns" == "0" ]]; then
        result_pass "User namespaces disabled" "max_user_namespaces=0"
    elif [[ "$userns" != "unknown" ]]; then
        result_warn "User namespaces enabled" "max_user_namespaces=${userns}" \
            "Set user.max_user_namespaces=0 if containers are not needed"
    fi

    # Randomize va_space (ASLR)
    local aslr
    aslr=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null || echo "unknown")
    if [[ "$aslr" == "2" ]]; then
        result_pass "Full ASLR enabled" "randomize_va_space=2"
    elif [[ "$aslr" == "1" ]]; then
        result_warn "Partial ASLR" "randomize_va_space=1" \
            "Set kernel.randomize_va_space=2 for full ASLR"
    else
        result_fail "ASLR disabled" "randomize_va_space=${aslr}" \
            "Set kernel.randomize_va_space=2 in /etc/sysctl.d/"
    fi
}
