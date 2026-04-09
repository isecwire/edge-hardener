#!/usr/bin/env bash
# edge-hardener — Bootloader security audit module
# Copyright (c) 2026 isecwire GmbH. MIT License.
#
# Sourced by edge_hardener.sh. Expects result_pass/result_fail/result_warn
# functions to be available in the caller's scope.

run_bootloader_audit() {
    _check_bootloader_type
    _check_grub_password
    _check_grub_permissions
    _check_uboot_security
    _check_secure_boot_chain
    _check_boot_partition
    _check_initramfs_security
}

# ---------------------------------------------------------------------------
# Bootloader type detection
# ---------------------------------------------------------------------------
_check_bootloader_type() {
    local grub_efi_found=0
    local cfg
    for cfg in /boot/efi/EFI/*/grub.cfg; do
        [[ -f "$cfg" ]] && grub_efi_found=1 && break
    done

    if [[ -f /boot/grub/grub.cfg ]] || [[ -f /boot/grub2/grub.cfg ]] || (( grub_efi_found )); then
        result_pass "Bootloader detected" "GRUB2"
    elif [[ -f /boot/grub/menu.lst ]]; then
        result_warn "GRUB Legacy detected" "Upgrade to GRUB2 for security features" \
            "Migrate to GRUB2 for password protection and Secure Boot support"
    elif [[ -f /proc/device-tree/model ]] 2>/dev/null; then
        # Likely an embedded system with U-Boot
        local model
        model=$(tr -d '\0' < /proc/device-tree/model 2>/dev/null || echo "unknown")
        # Check for U-Boot environment
        if command -v fw_printenv &>/dev/null; then
            result_pass "Bootloader detected" "U-Boot (${model})"
        elif [[ -f /etc/fw_env.config ]]; then
            result_pass "Bootloader detected" "U-Boot (env config present)"
        else
            result_warn "Embedded platform detected" "${model} — bootloader not identified" \
                "Ensure bootloader is properly secured"
        fi
    elif dmesg 2>/dev/null | grep -qi "u-boot\|uboot"; then
        result_pass "Bootloader detected" "U-Boot (from dmesg)"
    elif [[ -d /sys/firmware/efi ]]; then
        result_pass "UEFI firmware detected" "Bootloader managed by UEFI"
    else
        result_warn "Bootloader not identified" \
            "Cannot determine bootloader type" \
            "Manually verify bootloader security configuration"
    fi
}

# ---------------------------------------------------------------------------
# GRUB password protection
# ---------------------------------------------------------------------------
_check_grub_password() {
    local grub_cfg=""
    for cfg in /boot/grub/grub.cfg /boot/grub2/grub.cfg; do
        [[ -f "$cfg" ]] && grub_cfg="$cfg" && break
    done
    [[ -z "$grub_cfg" ]] && return

    # Check for password in grub.cfg
    if grep -q "password_pbkdf2\|set superusers" "$grub_cfg" 2>/dev/null; then
        result_pass "GRUB password protection enabled" "CIS 1.4.1 — superuser with PBKDF2"
    else
        # Also check custom config files
        local has_password=0
        for custom in /etc/grub.d/40_custom /etc/grub.d/01_users /etc/default/grub.d/*.cfg; do
            [[ -f "$custom" ]] || continue
            if grep -q "password_pbkdf2\|set superusers" "$custom" 2>/dev/null; then
                has_password=1
                break
            fi
        done

        if [[ "$has_password" -eq 1 ]]; then
            result_pass "GRUB password configured" "CIS 1.4.1 — in custom grub.d file"
        else
            result_fail "GRUB password not configured" \
                "CIS 1.4.1 — Anyone can edit boot parameters" \
                "Set GRUB password: grub-mkpasswd-pbkdf2, add to /etc/grub.d/40_custom"
        fi
    fi

    # Check for unrestricted menu entries
    if grep -q "^menuentry.*--unrestricted" "$grub_cfg" 2>/dev/null; then
        result_warn "GRUB has unrestricted menu entries" \
            "Some entries bypass password" \
            "Review menuentry options and remove --unrestricted where not needed"
    fi
}

# ---------------------------------------------------------------------------
# GRUB configuration file permissions
# ---------------------------------------------------------------------------
_check_grub_permissions() {
    local grub_files=(
        "/boot/grub/grub.cfg"
        "/boot/grub2/grub.cfg"
        "/boot/grub/grub.env"
        "/boot/grub2/grubenv"
    )

    for gf in "${grub_files[@]}"; do
        [[ -f "$gf" ]] || continue
        local perms owner
        perms=$(stat -c "%a" "$gf" 2>/dev/null || echo "unknown")
        owner=$(stat -c "%U:%G" "$gf" 2>/dev/null || echo "unknown")

        if [[ "$perms" == "600" ]] || [[ "$perms" == "400" ]] || [[ "$perms" == "700" ]]; then
            result_pass "$(basename "$gf") permissions" "mode ${perms}, owner ${owner}"
        elif [[ "$perms" == "644" ]]; then
            result_warn "$(basename "$gf") world-readable" \
                "CIS 1.4.1 — mode ${perms}" \
                "Set permissions: chmod 600 ${gf}"
        else
            result_fail "$(basename "$gf") permissions too open" \
                "mode ${perms}" \
                "Set permissions: chmod 600 ${gf}"
        fi
    done
}

# ---------------------------------------------------------------------------
# U-Boot security checks
# ---------------------------------------------------------------------------
_check_uboot_security() {
    if ! command -v fw_printenv &>/dev/null; then
        return
    fi

    # Check for U-Boot environment access control
    local env_config="/etc/fw_env.config"
    if [[ -f "$env_config" ]]; then
        local env_perms
        env_perms=$(stat -c "%a" "$env_config" 2>/dev/null || echo "unknown")
        if [[ "$env_perms" != "600" ]] && [[ "$env_perms" != "400" ]]; then
            result_warn "U-Boot env config permissions" \
                "mode ${env_perms} — should be 600" \
                "Set permissions: chmod 600 ${env_config}"
        else
            result_pass "U-Boot env config permissions" "mode ${env_perms}"
        fi
    fi

    # Check for bootdelay (allows interrupting boot)
    local bootdelay
    bootdelay=$(fw_printenv bootdelay 2>/dev/null | cut -d= -f2 || true)
    if [[ -n "$bootdelay" ]]; then
        if [[ "$bootdelay" == "0" ]] || [[ "$bootdelay" == "-1" ]] || [[ "$bootdelay" == "-2" ]]; then
            result_pass "U-Boot bootdelay" "bootdelay=${bootdelay} (no interactive interrupt)"
        else
            result_warn "U-Boot allows boot interrupt" \
                "bootdelay=${bootdelay} seconds" \
                "Set bootdelay to 0 or -2 to prevent unauthorized boot interruption"
        fi
    fi

    # Check for boot command verification
    local bootcmd
    bootcmd=$(fw_printenv bootcmd 2>/dev/null | cut -d= -f2 || true)
    if [[ -n "$bootcmd" ]]; then
        if echo "$bootcmd" | grep -q "verify\|hash\|secure"; then
            result_pass "U-Boot boot command includes verification" "Secure boot chain"
        else
            result_warn "U-Boot boot command lacks verification" \
                "Boot image integrity not checked" \
                "Enable U-Boot verified boot (FIT image verification)"
        fi
    fi

    # Check for U-Boot password
    local uboot_passwd
    uboot_passwd=$(fw_printenv 2>/dev/null | grep -i "^password\|^unlock" || true)
    if [[ -n "$uboot_passwd" ]]; then
        result_pass "U-Boot password configured"
    else
        result_warn "No U-Boot password detected" \
            "Console access unprotected" \
            "Configure U-Boot password protection"
    fi

    # Check if environment block can be written to by userspace
    if [[ -f "$env_config" ]]; then
        local env_device
        env_device=$(head -1 "$env_config" 2>/dev/null | awk '{print $1}' || true)
        if [[ -n "$env_device" ]] && [[ -w "$env_device" ]]; then
            result_warn "U-Boot environment device is writable" \
                "Non-root users may modify boot variables" \
                "Restrict access to U-Boot environment device"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Secure boot chain verification
# ---------------------------------------------------------------------------
_check_secure_boot_chain() {
    local sb_var_found=0
    local sb_file
    for sb_file in /sys/firmware/efi/efivars/SecureBoot-*; do
        [[ -f "$sb_file" ]] && sb_var_found=1 && break
    done

    # Check kernel image signature
    if [[ -f /proc/sys/kernel/moksbverify ]] || (( sb_var_found )); then
        # Read Secure Boot variable
        local sb_val
        for sb_file in /sys/firmware/efi/efivars/SecureBoot-*; do
            [[ -f "$sb_file" ]] || continue
            sb_val=$(od -An -t u1 -j4 -N1 "$sb_file" 2>/dev/null | tr -d ' ' || true)
            if [[ "$sb_val" == "1" ]]; then
                result_pass "UEFI Secure Boot verified active" "CIS 1.4.2"
            else
                result_warn "UEFI Secure Boot not active" \
                    "Boot chain not cryptographically verified" \
                    "Enable Secure Boot in UEFI firmware settings"
            fi
            break
        done
    fi

    # Check for signed kernel modules
    local sig_enforce
    sig_enforce=$(cat /proc/sys/kernel/module_sig_enforce 2>/dev/null || echo "unknown")
    if [[ "$sig_enforce" == "1" ]]; then
        result_pass "Kernel module signature enforcement" "module_sig_enforce=1"
    elif [[ "$sig_enforce" == "0" ]]; then
        result_warn "Kernel module signatures not enforced" \
            "Unsigned modules can be loaded" \
            "Enable module signature enforcement in kernel config"
    fi

    # Check for IMA (Integrity Measurement Architecture)
    if [[ -d /sys/kernel/security/ima ]]; then
        local ima_policy
        ima_policy=$(head -1 /sys/kernel/security/ima/policy 2>/dev/null || true)
        if [[ -n "$ima_policy" ]]; then
            result_pass "IMA (Integrity Measurement Architecture) active"
        else
            result_warn "IMA present but no policy loaded" \
                "File integrity measurements not enforced" \
                "Load an IMA policy via kernel command line or systemd"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Boot partition security
# ---------------------------------------------------------------------------
_check_boot_partition() {
    local boot_mount
    boot_mount=$(mount 2>/dev/null | grep " /boot " || true)

    if [[ -n "$boot_mount" ]]; then
        result_pass "/boot is a separate partition"

        # Check for read-only mount
        if echo "$boot_mount" | grep -q "\bro\b"; then
            result_pass "/boot mounted read-only"
        else
            result_warn "/boot not mounted read-only" \
                "Boot partition can be modified at runtime" \
                "Mount /boot as read-only: mount -o remount,ro /boot"
        fi
    else
        result_warn "/boot not a separate partition" \
            "CIS 1.1.7 — Boot files on root filesystem" \
            "Create a separate /boot partition for integrity protection"
    fi

    # Check boot directory permissions
    if [[ -d /boot ]]; then
        local boot_perms
        boot_perms=$(stat -c "%a" /boot 2>/dev/null || echo "unknown")
        if [[ "$boot_perms" == "700" ]] || [[ "$boot_perms" == "600" ]]; then
            result_pass "/boot directory permissions" "mode ${boot_perms}"
        elif [[ "$boot_perms" == "755" ]]; then
            result_warn "/boot directory world-readable" \
                "mode ${boot_perms}" \
                "Restrict access: chmod 700 /boot"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Initramfs security
# ---------------------------------------------------------------------------
_check_initramfs_security() {
    local initramfs_files
    initramfs_files=$(ls /boot/initrd* /boot/initramfs* 2>/dev/null || true)

    if [[ -z "$initramfs_files" ]]; then
        return
    fi

    while IFS= read -r initrd; do
        [[ -z "$initrd" ]] && continue
        [[ -f "$initrd" ]] || continue

        local perms
        perms=$(stat -c "%a" "$initrd" 2>/dev/null || echo "unknown")
        if [[ "$perms" == "600" ]] || [[ "$perms" == "400" ]]; then
            result_pass "$(basename "$initrd") permissions" "mode ${perms}"
        elif [[ "$perms" == "644" ]]; then
            result_warn "$(basename "$initrd") world-readable" \
                "May contain sensitive data (keys, credentials)" \
                "Set permissions: chmod 600 ${initrd}"
        fi
    done <<< "$initramfs_files"
}
