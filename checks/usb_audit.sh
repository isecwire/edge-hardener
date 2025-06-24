#!/usr/bin/env bash
# edge-hardener — USB device policy audit module
# Copyright (c) 2026 isecwire GmbH. MIT License.
#
# Sourced by edge_hardener.sh. Expects result_pass/result_fail/result_warn
# functions to be available in the caller's scope.

run_usb_audit() {
    _check_usb_authorized_default
    _check_usbguard
    _check_removable_media_mount
    _check_usb_storage_module
}

# ---------------------------------------------------------------------------
# Check USB authorized_default policy
# ---------------------------------------------------------------------------
_check_usb_authorized_default() {
    local auth_default_path="/sys/bus/usb/drivers_autoprobe"
    local auth_files
    auth_files=$(find /sys/bus/usb/devices/usb*/authorized_default 2>/dev/null | head -10)

    if [[ -z "$auth_files" ]]; then
        result_warn "USB authorized_default not found" \
            "Cannot determine USB device authorization policy" \
            "Ensure kernel supports USB authorization controls"
        return
    fi

    local all_restricted=1
    while IFS= read -r auth_file; do
        [[ -z "$auth_file" ]] && continue
        local val
        val=$(cat "$auth_file" 2>/dev/null || echo "unknown")
        if [[ "$val" != "0" ]]; then
            all_restricted=0
            break
        fi
    done <<< "$auth_files"

    if [[ "$all_restricted" -eq 1 ]]; then
        result_pass "USB authorized_default set to deny" \
            "New USB devices require explicit authorization"
    else
        result_warn "USB authorized_default allows new devices" \
            "New USB devices are automatically authorized" \
            "Set authorized_default=0 for USB host controllers: echo 0 > /sys/bus/usb/devices/usbN/authorized_default"
    fi
}

# ---------------------------------------------------------------------------
# Detect USBGuard installation and configuration
# ---------------------------------------------------------------------------
_check_usbguard() {
    if command -v usbguard &>/dev/null; then
        result_pass "USBGuard installed"

        # Check if the daemon is running
        if systemctl is-active usbguard.service &>/dev/null; then
            result_pass "USBGuard daemon active"
        else
            result_warn "USBGuard installed but daemon not active" \
                "USBGuard is not enforcing USB device policy" \
                "Enable and start USBGuard: systemctl enable --now usbguard.service"
        fi

        # Check for a policy file
        local policy_file="/etc/usbguard/rules.conf"
        if [[ -f "$policy_file" ]]; then
            local rule_count
            rule_count=$(grep -cvE '^\s*$|^\s*#' "$policy_file" 2>/dev/null || true)
            if [[ "$rule_count" -gt 0 ]]; then
                result_pass "USBGuard policy configured" "${rule_count} rule(s) defined"
            else
                result_warn "USBGuard policy file empty" \
                    "No USB authorization rules defined" \
                    "Configure USBGuard rules in ${policy_file}"
            fi
        else
            result_warn "USBGuard policy file not found" \
                "${policy_file} does not exist" \
                "Generate initial policy: usbguard generate-policy > ${policy_file}"
        fi
    else
        result_warn "USBGuard not installed" \
            "No USB device whitelisting framework" \
            "Install USBGuard for USB device authorization control: apt install usbguard / dnf install usbguard"
    fi
}

# ---------------------------------------------------------------------------
# Check for removable media mount policies
# ---------------------------------------------------------------------------
_check_removable_media_mount() {
    # Check if udisks2 automount is disabled
    local udisks_conf="/etc/udisks2/udisks2.conf"
    local polkit_dir="/etc/polkit-1/localauthority"
    local automount_restricted=0

    # Check udisks2 configuration
    if [[ -f "$udisks_conf" ]]; then
        if grep -qi "AutomaticMountOnLogin=false" "$udisks_conf" 2>/dev/null || \
           grep -qi "AutomaticMountOnHotplug=false" "$udisks_conf" 2>/dev/null; then
            automount_restricted=1
        fi
    fi

    # Check for fstab noauto/noexec on removable media mount points
    local fstab_removable=0
    if [[ -f /etc/fstab ]]; then
        if grep -qE "(noauto|noexec).*removable|/media.*noexec|/mnt.*noexec" /etc/fstab 2>/dev/null; then
            fstab_removable=1
        fi
    fi

    # Check udev rules for USB storage
    local udev_rules=0
    if [[ -d /etc/udev/rules.d ]]; then
        if grep -rq "usb.*storage\|SUBSYSTEM.*block.*removable" /etc/udev/rules.d/ 2>/dev/null; then
            udev_rules=1
        fi
    fi

    if [[ "$automount_restricted" -eq 1 ]]; then
        result_pass "Removable media automount restricted" "udisks2 automount disabled"
    elif [[ "$fstab_removable" -eq 1 ]]; then
        result_pass "Removable media mount options hardened" "noexec or noauto set in fstab"
    elif [[ "$udev_rules" -eq 1 ]]; then
        result_pass "USB storage udev rules present" "Custom udev rules for USB block devices"
    else
        result_warn "No removable media mount restrictions detected" \
            "USB storage devices may automount and allow execution" \
            "Disable automount via udisks2 or add noexec mount options for /media"
    fi
}

# ---------------------------------------------------------------------------
# Check USB mass storage kernel module status
# ---------------------------------------------------------------------------
_check_usb_storage_module() {
    # Check if usb-storage module is loaded
    if lsmod 2>/dev/null | grep -q "^usb_storage"; then
        result_warn "USB mass storage module loaded" \
            "usb_storage kernel module is active" \
            "Blacklist if not needed: echo 'blacklist usb_storage' > /etc/modprobe.d/disable-usb-storage.conf"
    else
        # Check if it's blacklisted
        local blacklisted=0
        if [[ -d /etc/modprobe.d ]]; then
            if grep -rq "blacklist.*usb.storage\|install.*usb.storage.*/bin/false\|install.*usb.storage.*/bin/true" \
                /etc/modprobe.d/ 2>/dev/null; then
                blacklisted=1
            fi
        fi

        if [[ "$blacklisted" -eq 1 ]]; then
            result_pass "USB mass storage module blacklisted" \
                "usb_storage blocked via modprobe.d"
        else
            result_pass "USB mass storage module not loaded" \
                "usb_storage not currently in use"
        fi
    fi

    # Check if usb-storage is compiled into the kernel (not a module)
    local kconfig=""
    for cfg in /boot/config-"$(uname -r)" /proc/config.gz; do
        [[ -f "$cfg" ]] && kconfig="$cfg" && break
    done

    if [[ -n "$kconfig" ]]; then
        local reader="cat"
        [[ "$kconfig" == *.gz ]] && reader="zcat"

        if $reader "$kconfig" 2>/dev/null | grep -q "CONFIG_USB_STORAGE=y"; then
            result_warn "USB mass storage compiled into kernel" \
                "Cannot be unloaded at runtime — built-in" \
                "Rebuild kernel with CONFIG_USB_STORAGE=m or CONFIG_USB_STORAGE=n"
        fi
    fi
}
