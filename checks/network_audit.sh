#!/usr/bin/env bash
# edge-hardener — Network exposure audit module
# Copyright (c) 2026 isecwire GmbH. MIT License.
#
# Sourced by edge_hardener.sh. Expects result_pass/result_fail/result_warn
# functions to be available in the caller's scope.

run_network_audit() {
    _check_listening_ports
    _check_risky_services
    _check_ip_forwarding
    _check_syn_cookies
    _check_icmp_redirects
    _check_rp_filter
}

# ---------------------------------------------------------------------------
# Listening ports
# ---------------------------------------------------------------------------
_check_listening_ports() {
    if ! command -v ss &>/dev/null; then
        result_warn "ss command not found" "Cannot enumerate listening ports" \
            "Install iproute2 package"
        return
    fi

    # TCP listeners
    local tcp_listeners
    tcp_listeners=$(ss -tlnp 2>/dev/null | tail -n +2 || true)
    local tcp_count
    tcp_count=$(echo "$tcp_listeners" | grep -c "LISTEN" || true)

    if [[ "$tcp_count" -gt 10 ]]; then
        result_warn "Many TCP listeners" "${tcp_count} ports open" \
            "Disable unnecessary services to reduce attack surface"
    else
        result_pass "TCP listener count" "${tcp_count} port(s)"
    fi

    # UDP listeners
    local udp_listeners
    udp_listeners=$(ss -ulnp 2>/dev/null | tail -n +2 || true)
    local udp_count
    udp_count=$(echo "$udp_listeners" | grep -c "UNCONN\|ESTAB" || true)

    if [[ "$udp_count" -gt 5 ]]; then
        result_warn "Many UDP listeners" "${udp_count} ports open" \
            "Review UDP services and disable unnecessary ones"
    else
        result_pass "UDP listener count" "${udp_count} port(s)"
    fi

    # Check for listeners on all interfaces (0.0.0.0 / ::)
    local wildcard_tcp
    wildcard_tcp=$(echo "$tcp_listeners" | grep -cE "0\.0\.0\.0:\*|:::|\*:" || true)
    if [[ "$wildcard_tcp" -gt 3 ]]; then
        result_warn "Services bound to all interfaces" "${wildcard_tcp} TCP wildcard listener(s)" \
            "Bind services to specific interfaces where possible"
    fi
}

# ---------------------------------------------------------------------------
# Risky services
# ---------------------------------------------------------------------------
_check_risky_services() {
    local listeners
    listeners=$(ss -tlnp 2>/dev/null || true)

    # Telnet
    if echo "$listeners" | grep -qE ":23[[:space:]]"; then
        result_fail "Telnet detected (port 23)" "Credentials sent in cleartext" \
            "Disable telnet and use SSH"
    fi

    # FTP
    if echo "$listeners" | grep -qE ":21[[:space:]]"; then
        result_warn "FTP detected (port 21)" "Credentials sent in cleartext" \
            "Replace with SFTP/SCP"
    fi

    # rsh / rlogin / rexec
    for port in 512 513 514; do
        if echo "$listeners" | grep -qE ":${port}[[:space:]]"; then
            result_fail "Legacy r-service on port ${port}" "Insecure remote access" \
                "Disable rsh/rlogin/rexec services"
        fi
    done

    # SNMP v1/v2 (typically 161/udp)
    local udp_listeners
    udp_listeners=$(ss -ulnp 2>/dev/null || true)
    if echo "$udp_listeners" | grep -qE ":161[[:space:]]"; then
        result_warn "SNMP detected (port 161)" "Ensure SNMPv3 with authentication" \
            "Upgrade to SNMPv3 or disable if not required"
    fi

    # Modbus TCP (common on edge/ICS devices)
    if echo "$listeners" | grep -qE ":502[[:space:]]"; then
        result_warn "Modbus TCP detected (port 502)" "Industrial protocol — no built-in auth" \
            "Restrict Modbus access via firewall rules"
    fi

    # MQTT (1883 unencrypted)
    if echo "$listeners" | grep -qE ":1883[[:space:]]"; then
        result_warn "MQTT (unencrypted) on port 1883" "" \
            "Use MQTT over TLS (port 8883) and require authentication"
    fi

    # OPC UA (4840 without TLS)
    if echo "$listeners" | grep -qE ":4840[[:space:]]"; then
        result_warn "OPC UA detected (port 4840)" "Verify TLS is enforced" \
            "Configure OPC UA Security Mode to SignAndEncrypt"
    fi
}

# ---------------------------------------------------------------------------
# IP forwarding
# ---------------------------------------------------------------------------
_check_ip_forwarding() {
    local ipv4_fwd
    ipv4_fwd=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "unknown")
    if [[ "$ipv4_fwd" == "0" ]]; then
        result_pass "IPv4 forwarding disabled"
    else
        result_warn "IPv4 forwarding enabled" "ip_forward=${ipv4_fwd}" \
            "Disable if not acting as router: sysctl net.ipv4.ip_forward=0"
    fi

    local ipv6_fwd
    ipv6_fwd=$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null || echo "unknown")
    if [[ "$ipv6_fwd" == "0" ]]; then
        result_pass "IPv6 forwarding disabled"
    else
        result_warn "IPv6 forwarding enabled" "ipv6 forwarding=${ipv6_fwd}" \
            "Disable if not needed: sysctl net.ipv6.conf.all.forwarding=0"
    fi
}

# ---------------------------------------------------------------------------
# SYN cookies
# ---------------------------------------------------------------------------
_check_syn_cookies() {
    local syn_cookies
    syn_cookies=$(cat /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null || echo "unknown")
    if [[ "$syn_cookies" == "1" ]]; then
        result_pass "TCP SYN cookies enabled"
    else
        result_warn "TCP SYN cookies disabled" "Susceptible to SYN flood attacks" \
            "Set net.ipv4.tcp_syncookies=1 in /etc/sysctl.d/"
    fi
}

# ---------------------------------------------------------------------------
# ICMP redirects
# ---------------------------------------------------------------------------
_check_icmp_redirects() {
    local accept_redirects
    accept_redirects=$(cat /proc/sys/net/ipv4/conf/all/accept_redirects 2>/dev/null || echo "unknown")
    if [[ "$accept_redirects" == "0" ]]; then
        result_pass "ICMP redirects rejected"
    else
        result_warn "ICMP redirects accepted" "accept_redirects=${accept_redirects}" \
            "Set net.ipv4.conf.all.accept_redirects=0"
    fi

    local send_redirects
    send_redirects=$(cat /proc/sys/net/ipv4/conf/all/send_redirects 2>/dev/null || echo "unknown")
    if [[ "$send_redirects" == "0" ]]; then
        result_pass "ICMP redirect sending disabled"
    else
        result_warn "ICMP redirect sending enabled" "send_redirects=${send_redirects}" \
            "Set net.ipv4.conf.all.send_redirects=0"
    fi
}

# ---------------------------------------------------------------------------
# Reverse path filtering
# ---------------------------------------------------------------------------
_check_rp_filter() {
    local rp_filter
    rp_filter=$(cat /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null || echo "unknown")
    if [[ "$rp_filter" == "1" ]] || [[ "$rp_filter" == "2" ]]; then
        result_pass "Reverse path filtering enabled" "rp_filter=${rp_filter}"
    else
        result_warn "Reverse path filtering disabled" "rp_filter=${rp_filter}" \
            "Set net.ipv4.conf.all.rp_filter=1 in /etc/sysctl.d/"
    fi
}
