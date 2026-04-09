#!/usr/bin/env bash
# edge-hardener — Cryptographic health audit module
# Copyright (c) 2026 isecwire GmbH. MIT License.
#
# Sourced by edge_hardener.sh. Expects result_pass/result_fail/result_warn
# functions to be available in the caller's scope.

run_crypto_audit() {
    _check_openssl_version
    _check_weak_ciphers_config
    _check_ssl_certificates
    _check_ssh_key_strength
    _check_tls_protocols
    _check_entropy_pool
    _check_rng_devices
}

# ---------------------------------------------------------------------------
# OpenSSL version
# ---------------------------------------------------------------------------
_check_openssl_version() {
    if ! command -v openssl &>/dev/null; then
        result_warn "OpenSSL not installed" "Cannot audit cryptographic configuration" \
            "Install openssl package"
        return
    fi

    local ossl_ver
    ossl_ver=$(openssl version 2>/dev/null || echo "unknown")
    local ver_num
    ver_num=$(echo "$ossl_ver" | grep -oP '\d+\.\d+\.\d+' | head -1 || echo "0.0.0")

    # Parse major.minor
    local major minor
    major=$(echo "$ver_num" | cut -d. -f1)
    minor=$(echo "$ver_num" | cut -d. -f2)

    if [[ "$major" -ge 3 ]]; then
        result_pass "OpenSSL version" "${ossl_ver} (3.x series)"
    elif [[ "$major" -eq 1 ]] && [[ "$minor" -ge 1 ]]; then
        result_warn "OpenSSL version" "${ossl_ver} — consider upgrading to 3.x" \
            "Upgrade to OpenSSL 3.x for latest security fixes"
    else
        result_fail "OpenSSL version outdated" "${ossl_ver}" \
            "Upgrade to OpenSSL 3.x immediately — known vulnerabilities in older versions"
    fi

    # Check for FIPS mode
    if openssl version 2>/dev/null | grep -qi "fips"; then
        result_pass "OpenSSL FIPS mode detected"
    fi
}

# ---------------------------------------------------------------------------
# Weak ciphers in configuration files
# ---------------------------------------------------------------------------
_check_weak_ciphers_config() {
    local weak_ciphers=("RC4" "DES" "3DES" "MD5" "SHA1" "NULL" "EXPORT" "aNULL" "eNULL")
    local configs_checked=0
    local weak_found=0

    # Check SSH config for weak ciphers
    if [[ -f /etc/ssh/sshd_config ]]; then
        local ssh_ciphers
        ssh_ciphers=$(grep -i "^Ciphers" /etc/ssh/sshd_config 2>/dev/null || true)
        for inc in /etc/ssh/sshd_config.d/*.conf; do
            [[ -f "$inc" ]] && ssh_ciphers+=" $(grep -i "^Ciphers" "$inc" 2>/dev/null || true)"
        done

        if echo "$ssh_ciphers" | grep -qi "3des\|arcfour\|blowfish\|cast128"; then
            result_fail "Weak SSH ciphers configured" \
                "Found weak cipher in sshd_config" \
                "Remove 3des-cbc, arcfour, blowfish-cbc, cast128-cbc from Ciphers list"
            ((weak_found++)) || true
        elif [[ -n "$ssh_ciphers" ]]; then
            result_pass "SSH ciphers configuration" "No weak ciphers detected"
        fi
        ((configs_checked++)) || true
    fi

    # Check SSH MAC algorithms
    if [[ -f /etc/ssh/sshd_config ]]; then
        local ssh_macs
        ssh_macs=$(grep -i "^MACs" /etc/ssh/sshd_config 2>/dev/null || true)
        for inc in /etc/ssh/sshd_config.d/*.conf; do
            [[ -f "$inc" ]] && ssh_macs+=" $(grep -i "^MACs" "$inc" 2>/dev/null || true)"
        done

        if echo "$ssh_macs" | grep -qi "hmac-md5\|hmac-sha1[^-]"; then
            result_warn "Weak SSH MAC algorithms configured" \
                "MD5 or plain SHA1 MACs found" \
                "Use hmac-sha2-256-etm or hmac-sha2-512-etm MACs"
            ((weak_found++)) || true
        fi
    fi

    # Check for weak ciphers in Apache/nginx configs
    local web_configs=()
    for f in /etc/nginx/nginx.conf /etc/nginx/conf.d/*.conf \
             /etc/apache2/mods-enabled/ssl.conf /etc/httpd/conf.d/ssl.conf; do
        [[ -f "$f" ]] && web_configs+=("$f")
    done

    for cfg in "${web_configs[@]}"; do
        local ssl_line
        ssl_line=$(grep -i "ssl_ciphers\|SSLCipherSuite" "$cfg" 2>/dev/null || true)
        if [[ -n "$ssl_line" ]]; then
            ((configs_checked++)) || true
            for weak in "${weak_ciphers[@]}"; do
                if echo "$ssl_line" | grep -qi "$weak"; then
                    result_warn "Weak cipher in ${cfg}" \
                        "Found reference to ${weak}" \
                        "Update cipher suite to remove ${weak} from ${cfg}"
                    ((weak_found++)) || true
                    break
                fi
            done
        fi
    done

    if [[ "$weak_found" -eq 0 ]] && [[ "$configs_checked" -gt 0 ]]; then
        result_pass "No weak ciphers in checked configurations" "${configs_checked} config(s) audited"
    fi
}

# ---------------------------------------------------------------------------
# SSL/TLS certificates
# ---------------------------------------------------------------------------
_check_ssl_certificates() {
    if ! command -v openssl &>/dev/null; then
        return
    fi

    local cert_dirs=("/etc/ssl/certs" "/etc/pki/tls/certs" "/etc/ssl/private")
    local expired_count=0
    local selfsigned_count=0
    local weak_key_count=0
    local certs_checked=0

    for certdir in "${cert_dirs[@]}"; do
        [[ -d "$certdir" ]] || continue
        # Check .pem and .crt files (limit to 20 for performance)
        local cert_files
        cert_files=$(find "$certdir" -maxdepth 2 -type f \( -name "*.pem" -o -name "*.crt" \) 2>/dev/null | head -20 || true)
        while IFS= read -r cert; do
            [[ -z "$cert" ]] && continue
            # Skip CA bundles and symlinks
            [[ -L "$cert" ]] && continue

            local enddate issuer subject keysize
            enddate=$(openssl x509 -enddate -noout -in "$cert" 2>/dev/null | cut -d= -f2 || true)
            [[ -z "$enddate" ]] && continue

            ((certs_checked++)) || true

            # Check expiration
            if ! openssl x509 -checkend 0 -noout -in "$cert" 2>/dev/null; then
                result_fail "Certificate expired: $(basename "$cert")" \
                    "Expired: ${enddate}" \
                    "Renew or replace certificate: ${cert}"
                ((expired_count++)) || true
                continue
            fi

            # Check expiring within 30 days
            if ! openssl x509 -checkend 2592000 -noout -in "$cert" 2>/dev/null; then
                result_warn "Certificate expiring soon: $(basename "$cert")" \
                    "Expires: ${enddate}" \
                    "Plan certificate renewal for: ${cert}"
            fi

            # Check self-signed
            issuer=$(openssl x509 -issuer -noout -in "$cert" 2>/dev/null || true)
            subject=$(openssl x509 -subject -noout -in "$cert" 2>/dev/null || true)
            if [[ "$issuer" == "$subject" ]] && [[ -n "$issuer" ]]; then
                # Skip known CA root certs
                if [[ "$cert" != *"/ca-certificates/"* ]] && [[ "$cert" != *"/mozilla/"* ]]; then
                    ((selfsigned_count++)) || true
                fi
            fi

            # Check key size
            keysize=$(openssl x509 -text -noout -in "$cert" 2>/dev/null | grep -oP 'Public-Key: \(\K\d+' || true)
            if [[ -n "$keysize" ]] && [[ "$keysize" -lt 2048 ]]; then
                result_fail "Weak key size in $(basename "$cert")" \
                    "${keysize}-bit key — minimum 2048 required" \
                    "Regenerate certificate with at least 2048-bit RSA or 256-bit EC key"
                ((weak_key_count++)) || true
            fi
        done <<< "$cert_files"
    done

    if [[ "$certs_checked" -gt 0 ]]; then
        if [[ "$expired_count" -eq 0 ]]; then
            result_pass "No expired certificates found" "${certs_checked} certificate(s) checked"
        fi
        if [[ "$selfsigned_count" -gt 0 ]]; then
            result_warn "Self-signed certificates detected" \
                "${selfsigned_count} self-signed cert(s) outside CA bundle" \
                "Replace self-signed certificates with CA-issued ones for production"
        fi
        if [[ "$weak_key_count" -eq 0 ]] && [[ "$certs_checked" -gt 0 ]]; then
            result_pass "Certificate key sizes adequate" "All keys >= 2048 bits"
        fi
    else
        result_pass "No local certificates to audit" "Standard CA bundle only"
    fi
}

# ---------------------------------------------------------------------------
# SSH key strength
# ---------------------------------------------------------------------------
_check_ssh_key_strength() {
    # Check SSH host keys
    local weak_host_keys=0
    for keyfile in /etc/ssh/ssh_host_*_key.pub; do
        [[ -f "$keyfile" ]] || continue
        local keytype keysize
        keytype=$(ssh-keygen -l -f "$keyfile" 2>/dev/null | awk '{print $NF}' | tr -d '()' || true)
        keysize=$(ssh-keygen -l -f "$keyfile" 2>/dev/null | awk '{print $1}' || true)

        if [[ "$keytype" == "DSA" ]]; then
            result_fail "DSA SSH host key present" "${keyfile} — DSA is deprecated" \
                "Remove DSA key and use Ed25519 or RSA >= 3072 bits"
            ((weak_host_keys++)) || true
        elif [[ "$keytype" == "RSA" ]] && [[ -n "$keysize" ]] && [[ "$keysize" -lt 3072 ]]; then
            result_warn "SSH host RSA key below 3072 bits" \
                "${keyfile}: ${keysize} bits" \
                "Regenerate with: ssh-keygen -t rsa -b 4096 -f ${keyfile%.pub}"
            ((weak_host_keys++)) || true
        elif [[ "$keytype" == "ECDSA" ]]; then
            result_pass "SSH host ECDSA key" "${keyfile}: ${keysize} bits"
        elif [[ "$keytype" == "ED25519" ]]; then
            result_pass "SSH host Ed25519 key" "${keyfile}: ${keysize} bits"
        fi
    done

    if [[ "$weak_host_keys" -eq 0 ]]; then
        local host_key_count
        host_key_count=$(find /etc/ssh/ -maxdepth 1 -name 'ssh_host_*_key.pub' 2>/dev/null | wc -l)
        if [[ "$host_key_count" -gt 0 ]]; then
            result_pass "SSH host key strength adequate" "${host_key_count} key(s) checked"
        fi
    fi

    # Check authorized_keys for weak keys
    local weak_user_keys=0
    for homedir in /root /home/*; do
        local authkeys="${homedir}/.ssh/authorized_keys"
        [[ -f "$authkeys" ]] || continue
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            [[ "$line" == "#"* ]] && continue
            if echo "$line" | grep -q "^ssh-dss"; then
                result_warn "DSA key in ${authkeys}" "DSA keys are deprecated" \
                    "Replace DSA authorized key with Ed25519 or RSA >= 3072"
                ((weak_user_keys++)) || true
            fi
            if echo "$line" | grep -q "^ssh-rsa"; then
                local tmpkey
                tmpkey=$(mktemp 2>/dev/null || echo "")
                if [[ -n "$tmpkey" ]]; then
                    echo "$line" > "$tmpkey"
                    local ukey_size
                    ukey_size=$(ssh-keygen -l -f "$tmpkey" 2>/dev/null | awk '{print $1}' || true)
                    rm -f "$tmpkey"
                    if [[ -n "$ukey_size" ]] && [[ "$ukey_size" -lt 2048 ]]; then
                        result_warn "Weak RSA key in ${authkeys}" \
                            "${ukey_size}-bit RSA key" \
                            "Replace with Ed25519 or RSA >= 3072 bits"
                        ((weak_user_keys++)) || true
                    fi
                fi
            fi
        done < "$authkeys"
    done
}

# ---------------------------------------------------------------------------
# TLS protocol versions
# ---------------------------------------------------------------------------
_check_tls_protocols() {
    # Check for TLS 1.0/1.1 in SSH kex algorithms
    if [[ -f /etc/ssh/sshd_config ]]; then
        local kex_algs
        kex_algs=$(grep -i "^KexAlgorithms" /etc/ssh/sshd_config 2>/dev/null || true)
        if echo "$kex_algs" | grep -qi "diffie-hellman-group1-sha1\|diffie-hellman-group-exchange-sha1"; then
            result_fail "Weak SSH key exchange algorithms" \
                "SHA1-based KEX algorithms configured" \
                "Remove diffie-hellman-group1-sha1 and group-exchange-sha1 from KexAlgorithms"
        fi
    fi

    # Check if TLS 1.0/1.1 is disabled system-wide (crypto-policies on RHEL/Fedora)
    if [[ -f /etc/crypto-policies/config ]]; then
        local policy
        policy=$(cat /etc/crypto-policies/config 2>/dev/null || echo "unknown")
        if [[ "$policy" == "DEFAULT" ]] || [[ "$policy" == "FUTURE" ]] || [[ "$policy" == "FIPS" ]]; then
            result_pass "System crypto policy" "${policy}"
        elif [[ "$policy" == "LEGACY" ]]; then
            result_warn "System crypto policy is LEGACY" \
                "Allows weak algorithms" \
                "Set to DEFAULT or FUTURE: update-crypto-policies --set DEFAULT"
        fi
    fi

    # Check OpenSSL default min protocol
    if [[ -f /etc/ssl/openssl.cnf ]]; then
        local min_proto
        min_proto=$(grep -i "MinProtocol" /etc/ssl/openssl.cnf 2>/dev/null | head -1 || true)
        if [[ -n "$min_proto" ]]; then
            if echo "$min_proto" | grep -qi "TLSv1.2\|TLSv1.3"; then
                result_pass "OpenSSL minimum protocol" "$min_proto"
            elif echo "$min_proto" | grep -qi "TLSv1$\|TLSv1.0\|TLSv1.1\|SSLv"; then
                result_fail "OpenSSL allows legacy TLS" "$min_proto" \
                    "Set MinProtocol = TLSv1.2 in /etc/ssl/openssl.cnf"
            fi
        fi
    fi
}

# ---------------------------------------------------------------------------
# Entropy pool
# ---------------------------------------------------------------------------
_check_entropy_pool() {
    local entropy
    entropy=$(cat /proc/sys/kernel/random/entropy_avail 2>/dev/null || echo "unknown")

    if [[ "$entropy" == "unknown" ]]; then
        result_warn "Cannot read entropy pool size"
        return
    fi

    if [[ "$entropy" -ge 256 ]]; then
        result_pass "Entropy pool adequate" "${entropy} bits available"
    elif [[ "$entropy" -ge 128 ]]; then
        result_warn "Low entropy pool" "${entropy} bits — may affect crypto operations" \
            "Install haveged or rng-tools for additional entropy"
    else
        result_fail "Critically low entropy" "${entropy} bits available" \
            "Install haveged or rng-tools immediately for cryptographic safety"
    fi
}

# ---------------------------------------------------------------------------
# Hardware RNG
# ---------------------------------------------------------------------------
_check_rng_devices() {
    if [[ -c /dev/hwrng ]]; then
        result_pass "Hardware RNG available" "/dev/hwrng present"
    else
        result_warn "No hardware RNG detected" "/dev/hwrng not present" \
            "Consider using rng-tools with CPU RDRAND or external HRNG"
    fi

    # Check if rngd is running
    if pgrep -x rngd &>/dev/null || systemctl is-active rng-tools &>/dev/null 2>&1; then
        result_pass "RNG daemon running" "rngd or rng-tools active"
    fi
}
