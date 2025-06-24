#!/usr/bin/env bash
# edge-hardener — Filesystem permission audit module
# Copyright (c) 2026 isecwire GmbH. MIT License.
#
# Sourced by edge_hardener.sh. Expects result_pass/result_fail/result_warn
# functions to be available in the caller's scope.

run_filesystem_audit() {
    _check_world_writable
    _check_suid_sgid
    _check_tmp_mount
    _check_sensitive_files
    _check_noexec_mounts
}

# ---------------------------------------------------------------------------
# World-writable files and directories
# ---------------------------------------------------------------------------
_check_world_writable() {
    # Directories (excluding standard tmpfs locations)
    local ww_dirs
    ww_dirs=$(find / -maxdepth 3 -type d -perm -0002 \
        ! -path "/tmp" ! -path "/tmp/*" \
        ! -path "/var/tmp" ! -path "/var/tmp/*" \
        ! -path "/dev/*" ! -path "/proc/*" ! -path "/sys/*" \
        ! -path "/run/*" ! -path "/dev/shm" ! -path "/dev/shm/*" \
        2>/dev/null | head -20 || true)
    local ww_dir_count
    ww_dir_count=$(echo "$ww_dirs" | grep -c "." || true)

    if [[ "$ww_dir_count" -gt 0 ]]; then
        result_warn "World-writable directories" "${ww_dir_count} found outside /tmp, /var/tmp" \
            "Review and restrict: chmod o-w <dir>, or set sticky bit: chmod +t <dir>"
    else
        result_pass "No unexpected world-writable directories"
    fi

    # World-writable files (non-symlinks)
    local ww_files
    ww_files=$(find /etc /usr /opt -maxdepth 3 -type f -perm -0002 \
        2>/dev/null | head -20 || true)
    local ww_file_count
    ww_file_count=$(echo "$ww_files" | grep -c "." || true)

    if [[ "$ww_file_count" -gt 0 ]]; then
        result_fail "World-writable files in system paths" "${ww_file_count} found" \
            "Fix permissions: chmod o-w on affected files"
    else
        result_pass "No world-writable files in /etc, /usr, /opt"
    fi
}

# ---------------------------------------------------------------------------
# SUID / SGID binaries
# ---------------------------------------------------------------------------
_check_suid_sgid() {
    # SUID
    local suid_bins
    suid_bins=$(find / -maxdepth 4 -type f -perm -4000 \
        ! -path "/proc/*" ! -path "/sys/*" ! -path "/snap/*" \
        2>/dev/null | sort || true)
    local suid_count
    suid_count=$(echo "$suid_bins" | grep -c "." || true)

    # Known acceptable SUID binaries on minimal systems
    local known_suid=(
        "/usr/bin/passwd"
        "/usr/bin/sudo"
        "/usr/bin/su"
        "/usr/bin/newgrp"
        "/usr/bin/chsh"
        "/usr/bin/chfn"
        "/usr/bin/gpasswd"
        "/usr/bin/mount"
        "/usr/bin/umount"
        "/usr/bin/pkexec"
        "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
    )

    local unexpected=0
    while IFS= read -r bin; do
        [[ -z "$bin" ]] && continue
        local is_known=0
        for known in "${known_suid[@]}"; do
            if [[ "$bin" == "$known" ]]; then
                is_known=1
                break
            fi
        done
        if [[ "$is_known" -eq 0 ]]; then
            ((unexpected++)) || true
        fi
    done <<< "$suid_bins"

    if [[ "$suid_count" -eq 0 ]]; then
        result_pass "No SUID binaries found" "Minimal installation"
    elif [[ "$unexpected" -gt 0 ]]; then
        result_warn "SUID binaries audit" "${suid_count} total, ${unexpected} non-standard" \
            "Review SUID binaries: remove with chmod u-s or replace with capabilities"
    else
        result_pass "SUID binaries" "${suid_count} found (all standard)"
    fi

    # SGID
    local sgid_bins
    sgid_bins=$(find / -maxdepth 4 -type f -perm -2000 \
        ! -path "/proc/*" ! -path "/sys/*" ! -path "/snap/*" \
        2>/dev/null | head -30 || true)
    local sgid_count
    sgid_count=$(echo "$sgid_bins" | grep -c "." || true)

    if [[ "$sgid_count" -gt 10 ]]; then
        result_warn "SGID binary count" "${sgid_count} SGID binaries — review for necessity" \
            "Audit SGID binaries and remove unnecessary ones"
    else
        result_pass "SGID binary count" "${sgid_count} found"
    fi
}

# ---------------------------------------------------------------------------
# /tmp mount options
# ---------------------------------------------------------------------------
_check_tmp_mount() {
    local tmp_mount
    tmp_mount=$(mount 2>/dev/null | grep " /tmp " || true)

    if [[ -z "$tmp_mount" ]]; then
        result_warn "/tmp not a separate mount" "Cannot enforce noexec/nosuid" \
            "Mount /tmp as tmpfs with noexec,nosuid,nodev options"
        return
    fi

    if echo "$tmp_mount" | grep -q "noexec"; then
        result_pass "/tmp mounted with noexec"
    else
        result_warn "/tmp missing noexec" "" \
            "Add noexec to /tmp mount options in /etc/fstab"
    fi

    if echo "$tmp_mount" | grep -q "nosuid"; then
        result_pass "/tmp mounted with nosuid"
    else
        result_warn "/tmp missing nosuid" "" \
            "Add nosuid to /tmp mount options in /etc/fstab"
    fi

    if echo "$tmp_mount" | grep -q "nodev"; then
        result_pass "/tmp mounted with nodev"
    else
        result_warn "/tmp missing nodev" "" \
            "Add nodev to /tmp mount options in /etc/fstab"
    fi
}

# ---------------------------------------------------------------------------
# Sensitive file permissions
# ---------------------------------------------------------------------------
_check_sensitive_files() {
    # /etc/shadow
    if [[ -f /etc/shadow ]]; then
        local shadow_perms
        shadow_perms=$(stat -c "%a" /etc/shadow 2>/dev/null || echo "unknown")
        if [[ "$shadow_perms" == "640" ]] || [[ "$shadow_perms" == "600" ]] || [[ "$shadow_perms" == "000" ]]; then
            result_pass "/etc/shadow permissions" "mode ${shadow_perms}"
        else
            result_fail "/etc/shadow permissions too open" "mode ${shadow_perms}" \
                "Set permissions: chmod 640 /etc/shadow"
        fi
    fi

    # /etc/gshadow
    if [[ -f /etc/gshadow ]]; then
        local gshadow_perms
        gshadow_perms=$(stat -c "%a" /etc/gshadow 2>/dev/null || echo "unknown")
        if [[ "$gshadow_perms" == "640" ]] || [[ "$gshadow_perms" == "600" ]] || [[ "$gshadow_perms" == "000" ]]; then
            result_pass "/etc/gshadow permissions" "mode ${gshadow_perms}"
        else
            result_fail "/etc/gshadow permissions too open" "mode ${gshadow_perms}" \
                "Set permissions: chmod 640 /etc/gshadow"
        fi
    fi

    # SSH host keys
    local bad_ssh_keys=0
    for key in /etc/ssh/ssh_host_*_key; do
        [[ -f "$key" ]] || continue
        local key_perms
        key_perms=$(stat -c "%a" "$key" 2>/dev/null || echo "unknown")
        if [[ "$key_perms" != "600" ]] && [[ "$key_perms" != "400" ]]; then
            ((bad_ssh_keys++)) || true
        fi
    done

    if [[ "$bad_ssh_keys" -gt 0 ]]; then
        result_fail "SSH host key permissions" "${bad_ssh_keys} key(s) with wrong permissions" \
            "Set permissions: chmod 600 /etc/ssh/ssh_host_*_key"
    else
        result_pass "SSH host key permissions" "All private keys properly restricted"
    fi

    # /etc/crontab
    if [[ -f /etc/crontab ]]; then
        local crontab_perms
        crontab_perms=$(stat -c "%a" /etc/crontab 2>/dev/null || echo "unknown")
        if [[ "$crontab_perms" == "600" ]] || [[ "$crontab_perms" == "644" ]]; then
            result_pass "/etc/crontab permissions" "mode ${crontab_perms}"
        else
            result_warn "/etc/crontab permissions" "mode ${crontab_perms}" \
                "Set permissions: chmod 600 /etc/crontab"
        fi
    fi
}

# ---------------------------------------------------------------------------
# noexec on removable / data mounts
# ---------------------------------------------------------------------------
_check_noexec_mounts() {
    # Check common data mounts for noexec
    local data_mounts
    data_mounts=$(mount 2>/dev/null | grep -E "/media/|/mnt/|/srv/" || true)

    if [[ -n "$data_mounts" ]]; then
        local missing_noexec=0
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            if ! echo "$line" | grep -q "noexec"; then
                ((missing_noexec++)) || true
            fi
        done <<< "$data_mounts"

        if [[ "$missing_noexec" -gt 0 ]]; then
            result_warn "Data mounts without noexec" "${missing_noexec} mount(s)" \
                "Add noexec to data/removable mounts in /etc/fstab"
        else
            result_pass "Data mounts have noexec" "All /media, /mnt, /srv mounts"
        fi
    fi
}
