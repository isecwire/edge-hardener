#!/usr/bin/env bash
# edge-hardener — Binary provenance & supply chain audit module
# Copyright (c) 2026 isecwire GmbH. MIT License.
#
# Sourced by edge_hardener.sh. Expects result_pass/result_fail/result_warn
# functions to be available in the caller's scope.

run_supply_chain_audit() {
    _check_binary_hardening
    _check_stripped_binaries
    _check_library_versions
    _check_package_signatures
    _check_binary_provenance
    _check_writable_library_paths
}

# ---------------------------------------------------------------------------
# Binary hardening flags (RELRO, PIE, stack canary, NX, FORTIFY)
# ---------------------------------------------------------------------------
_check_binary_hardening() {
    if ! command -v readelf &>/dev/null; then
        result_warn "readelf not installed" "Cannot audit binary hardening flags" \
            "Install binutils package for binary analysis"
        return
    fi

    # Critical system binaries to audit
    local critical_bins=(
        "/usr/sbin/sshd"
        "/usr/bin/sudo"
        "/usr/bin/su"
        "/usr/bin/login"
        "/usr/bin/passwd"
        "/usr/sbin/nginx"
        "/usr/sbin/apache2"
        "/usr/sbin/httpd"
        "/usr/bin/mosquitto"
        "/usr/bin/node"
        "/usr/bin/python3"
    )

    local checked=0
    local no_pie=0
    local no_relro=0
    local no_canary=0
    local no_nx=0

    for bin in "${critical_bins[@]}"; do
        [[ -f "$bin" ]] || continue
        [[ -x "$bin" ]] || continue
        ((checked++)) || true

        local binname
        binname=$(basename "$bin")

        # Check PIE (Position Independent Executable)
        local elf_type
        elf_type=$(readelf -h "$bin" 2>/dev/null | grep "Type:" || true)
        if echo "$elf_type" | grep -q "DYN"; then
            : # PIE or shared object — good
        elif echo "$elf_type" | grep -q "EXEC"; then
            result_warn "${binname}: not compiled as PIE" \
                "IEC 62443-4-1 CR 3.4 — Position-independent executable" \
                "Recompile ${binname} with -fPIE -pie flags"
            ((no_pie++)) || true
        fi

        # Check RELRO (Relocation Read-Only)
        local relro_flags
        relro_flags=$(readelf -l "$bin" 2>/dev/null | grep "GNU_RELRO" || true)
        local bind_now
        bind_now=$(readelf -d "$bin" 2>/dev/null | grep "BIND_NOW\|FLAGS.*NOW" || true)

        if [[ -n "$relro_flags" ]] && [[ -n "$bind_now" ]]; then
            : # Full RELRO — best
        elif [[ -n "$relro_flags" ]]; then
            result_warn "${binname}: partial RELRO only" \
                "Full RELRO (BIND_NOW) recommended" \
                "Recompile with -Wl,-z,relro,-z,now"
        else
            result_fail "${binname}: no RELRO protection" \
                "GOT overwrite attacks possible" \
                "Recompile with -Wl,-z,relro,-z,now"
            ((no_relro++)) || true
        fi

        # Check stack canary
        local has_canary
        has_canary=$(readelf -s "$bin" 2>/dev/null | grep "__stack_chk_fail\|__stack_chk_guard" || true)
        if [[ -z "$has_canary" ]]; then
            result_warn "${binname}: no stack canary detected" \
                "Buffer overflow protection missing" \
                "Recompile with -fstack-protector-strong"
            ((no_canary++)) || true
        fi

        # Check NX (No-Execute) bit
        local nx_flag
        nx_flag=$(readelf -l "$bin" 2>/dev/null | grep "GNU_STACK" || true)
        if echo "$nx_flag" | grep -q "RWE"; then
            result_fail "${binname}: executable stack (NX disabled)" \
                "Stack-based code execution possible" \
                "Recompile without -z execstack"
            ((no_nx++)) || true
        fi

        # Check FORTIFY_SOURCE
        local fortify
        fortify=$(readelf -s "$bin" 2>/dev/null | grep "__.*_chk@\|__fortify" || true)
        if [[ -z "$fortify" ]]; then
            # Not all binaries use fortified functions, so this is informational
            :
        fi
    done

    if [[ "$checked" -eq 0 ]]; then
        result_pass "No standard critical binaries to audit" "Custom embedded system"
        return
    fi

    # Summary results
    if [[ "$no_pie" -eq 0 ]]; then
        result_pass "All critical binaries compiled as PIE" "${checked} binary(ies) checked"
    fi
    if [[ "$no_relro" -eq 0 ]] && [[ "$checked" -gt 0 ]]; then
        result_pass "All critical binaries have RELRO" "${checked} binary(ies) checked"
    fi
    if [[ "$no_canary" -eq 0 ]] && [[ "$checked" -gt 0 ]]; then
        result_pass "All critical binaries have stack canary" "${checked} binary(ies) checked"
    fi
    if [[ "$no_nx" -eq 0 ]] && [[ "$checked" -gt 0 ]]; then
        result_pass "All critical binaries have NX (non-executable stack)" "${checked} binary(ies) checked"
    fi
}

# ---------------------------------------------------------------------------
# Stripped binaries
# ---------------------------------------------------------------------------
_check_stripped_binaries() {
    if ! command -v file &>/dev/null; then
        result_warn "file command not available" "Cannot check binary stripping"
        return
    fi

    local bins_to_check=(
        "/usr/sbin/sshd"
        "/usr/bin/sudo"
        "/usr/bin/su"
        "/usr/bin/login"
    )

    local unstripped=0
    local checked=0
    for bin in "${bins_to_check[@]}"; do
        [[ -f "$bin" ]] || continue
        ((checked++)) || true
        if file "$bin" 2>/dev/null | grep -q "not stripped"; then
            result_warn "$(basename "$bin"): not stripped" \
                "Debug symbols present in production binary" \
                "Strip binary: strip --strip-all ${bin}"
            ((unstripped++)) || true
        fi
    done

    if [[ "$checked" -gt 0 ]] && [[ "$unstripped" -eq 0 ]]; then
        result_pass "Critical binaries are stripped" "${checked} binary(ies) checked"
    fi
}

# ---------------------------------------------------------------------------
# Known-vulnerable library versions
# ---------------------------------------------------------------------------
_check_library_versions() {
    # Check for known-vulnerable library patterns
    local vuln_found=0

    # OpenSSL < 1.1.1
    if command -v openssl &>/dev/null; then
        local ossl_ver
        ossl_ver=$(openssl version 2>/dev/null | grep -oP '\d+\.\d+\.\d+[a-z]*' | head -1 || true)
        if [[ -n "$ossl_ver" ]]; then
            local major minor patch
            major=$(echo "$ossl_ver" | cut -d. -f1)
            minor=$(echo "$ossl_ver" | cut -d. -f2)
            patch=$(echo "$ossl_ver" | cut -d. -f3 | tr -d '[:alpha:]')
            if [[ "$major" -eq 1 ]] && [[ "$minor" -eq 0 ]]; then
                result_fail "OpenSSL 1.0.x detected" "Version ${ossl_ver} — EOL, many CVEs" \
                    "Upgrade to OpenSSL 3.x immediately"
                ((vuln_found++)) || true
            fi
        fi
    fi

    # glibc version check
    local glibc_ver
    glibc_ver=$(ldd --version 2>&1 | head -1 | grep -oP '\d+\.\d+' || true)
    if [[ -n "$glibc_ver" ]]; then
        local glibc_major glibc_minor
        glibc_major=$(echo "$glibc_ver" | cut -d. -f1)
        glibc_minor=$(echo "$glibc_ver" | cut -d. -f2)
        if [[ "$glibc_major" -eq 2 ]] && [[ "$glibc_minor" -lt 31 ]]; then
            result_warn "glibc version ${glibc_ver}" \
                "Older glibc may contain known vulnerabilities" \
                "Update glibc to latest available version for your distribution"
            ((vuln_found++)) || true
        else
            result_pass "glibc version" "${glibc_ver}"
        fi
    fi

    # libcurl version
    if command -v curl &>/dev/null; then
        local curl_ver
        curl_ver=$(curl --version 2>/dev/null | head -1 | grep -oP '\d+\.\d+\.\d+' | head -1 || true)
        if [[ -n "$curl_ver" ]]; then
            local curl_major curl_minor
            curl_major=$(echo "$curl_ver" | cut -d. -f1)
            curl_minor=$(echo "$curl_ver" | cut -d. -f2)
            if [[ "$curl_major" -eq 7 ]] && [[ "$curl_minor" -lt 79 ]]; then
                result_warn "curl/libcurl ${curl_ver}" \
                    "Older versions have known CVEs" \
                    "Update curl to latest version"
            else
                result_pass "curl version" "${curl_ver}"
            fi
        fi
    fi

    # Check for outdated shared libraries
    if command -v ldconfig &>/dev/null; then
        # Check for multiple versions of the same library (upgrade residue)
        local dup_libs
        dup_libs=$(ldconfig -p 2>/dev/null | awk -F'=>' '{print $2}' | \
            xargs -I{} dirname {} 2>/dev/null | sort | uniq -c | \
            sort -rn | head -5 || true)
        # This is informational, not a direct vulnerability
    fi

    if [[ "$vuln_found" -eq 0 ]]; then
        result_pass "No known-vulnerable library versions detected"
    fi
}

# ---------------------------------------------------------------------------
# Package signature verification
# ---------------------------------------------------------------------------
_check_package_signatures() {
    # APT-based systems
    if command -v apt-get &>/dev/null; then
        if [[ -f /etc/apt/apt.conf.d/99allow-unauthenticated ]] || \
           grep -rq "AllowUnauthenticated" /etc/apt/apt.conf.d/ 2>/dev/null; then
            result_fail "APT allows unauthenticated packages" \
                "Package signature verification disabled" \
                "Remove AllowUnauthenticated from apt configuration"
        else
            result_pass "APT package signature verification enabled"
        fi

        # Check for unsigned repositories
        local unsigned_repos
        unsigned_repos=$(grep -r "trusted=yes" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null | head -5 || true)
        if [[ -n "$unsigned_repos" ]]; then
            result_warn "APT repositories with trusted=yes" \
                "Some repositories bypass signature verification" \
                "Remove trusted=yes from repository definitions"
        fi
    fi

    # RPM-based systems
    if command -v rpm &>/dev/null; then
        local gpgcheck
        gpgcheck=$(grep -r "^gpgcheck" /etc/yum.repos.d/ 2>/dev/null | grep "=0" || true)
        if [[ -n "$gpgcheck" ]]; then
            result_fail "RPM repositories with gpgcheck=0" \
                "Package signature verification disabled" \
                "Set gpgcheck=1 in all repository configurations"
        else
            result_pass "RPM package signature verification enabled"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Binary provenance
# ---------------------------------------------------------------------------
_check_binary_provenance() {
    # Check for binaries not owned by any package
    local unowned=0

    if command -v dpkg &>/dev/null; then
        # Check a few key binaries
        for bin in /usr/local/bin/*; do
            [[ -f "$bin" ]] || continue
            [[ -x "$bin" ]] || continue
            if ! dpkg -S "$bin" &>/dev/null; then
                ((unowned++)) || true
            fi
        done
    elif command -v rpm &>/dev/null; then
        for bin in /usr/local/bin/*; do
            [[ -f "$bin" ]] || continue
            [[ -x "$bin" ]] || continue
            if ! rpm -qf "$bin" &>/dev/null; then
                ((unowned++)) || true
            fi
        done
    fi

    if [[ "$unowned" -gt 5 ]]; then
        result_warn "Unpackaged binaries in /usr/local/bin" \
            "${unowned} executable(s) not from package manager" \
            "Audit unpackaged binaries for provenance and integrity"
    elif [[ "$unowned" -gt 0 ]]; then
        result_pass "Few unpackaged binaries" "${unowned} in /usr/local/bin"
    fi
}

# ---------------------------------------------------------------------------
# Writable library paths
# ---------------------------------------------------------------------------
_check_writable_library_paths() {
    local lib_paths=("/usr/lib" "/usr/lib64" "/lib" "/lib64")
    local writable_found=0

    for libdir in "${lib_paths[@]}"; do
        [[ -d "$libdir" ]] || continue
        # Check if the directory itself is world-writable
        local perms
        perms=$(stat -c "%a" "$libdir" 2>/dev/null || echo "000")
        if [[ "${perms: -1}" -ge 2 ]]; then
            result_fail "Library directory world-writable: ${libdir}" \
                "mode ${perms} — library injection risk" \
                "Fix permissions: chmod o-w ${libdir}"
            ((writable_found++)) || true
        fi
    done

    # Check LD_LIBRARY_PATH in system profiles
    local ld_path_set=0
    for profile in /etc/profile /etc/profile.d/*.sh /etc/environment; do
        [[ -f "$profile" ]] || continue
        if grep -q "LD_LIBRARY_PATH" "$profile" 2>/dev/null; then
            result_warn "LD_LIBRARY_PATH set in ${profile}" \
                "Custom library search path may enable injection" \
                "Remove LD_LIBRARY_PATH from system-wide profiles"
            ((ld_path_set++)) || true
        fi
    done

    # Check LD_PRELOAD
    if [[ -f /etc/ld.so.preload ]]; then
        local preload_entries
        preload_entries=$(grep -v "^#" /etc/ld.so.preload 2>/dev/null | grep -c "." || true)
        if [[ "$preload_entries" -gt 0 ]]; then
            result_warn "LD preload entries found" \
                "${preload_entries} entries in /etc/ld.so.preload" \
                "Audit /etc/ld.so.preload for unauthorized library injection"
        fi
    fi

    if [[ "$writable_found" -eq 0 ]]; then
        result_pass "Library directories not world-writable"
    fi
}
