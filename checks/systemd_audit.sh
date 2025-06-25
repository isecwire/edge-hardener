#!/usr/bin/env bash
# edge-hardener — systemd service hardening audit module
# Copyright (c) 2026 isecwire GmbH. MIT License.
#
# Sourced by edge_hardener.sh. Expects result_pass/result_fail/result_warn
# functions to be available in the caller's scope.

run_systemd_audit() {
    _check_service_hardening
    _check_root_services_without_hardening
    _check_unnecessary_services
}

# ---------------------------------------------------------------------------
# Check running services for security hardening directives
# ---------------------------------------------------------------------------
_check_service_hardening() {
    if ! command -v systemctl &>/dev/null; then
        result_warn "systemctl not available" "Cannot audit systemd service hardening"
        return
    fi

    local directives=("ProtectSystem" "ProtectHome" "NoNewPrivileges" "PrivateTmp" "CapabilityBoundingSet")
    local hardened_count=0
    local unhardened_count=0
    local unhardened_list=""

    # Get list of running non-oneshot services
    local services
    services=$(systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null \
        | awk '{print $1}' | head -50)

    if [[ -z "$services" ]]; then
        result_warn "No running systemd services detected" "Cannot evaluate service hardening"
        return
    fi

    while IFS= read -r svc; do
        [[ -z "$svc" ]] && continue
        local props
        props=$(systemctl show "$svc" --no-pager \
            --property=ProtectSystem,ProtectHome,NoNewPrivileges,PrivateTmp,CapabilityBoundingSet \
            2>/dev/null || true)
        [[ -z "$props" ]] && continue

        local score=0

        # ProtectSystem: strict or full is good, true is acceptable
        if echo "$props" | grep -q "ProtectSystem=strict\|ProtectSystem=full\|ProtectSystem=true\|ProtectSystem=yes"; then
            score=$((score + 1))
        fi

        # ProtectHome: true, yes, read-only, or tmpfs
        if echo "$props" | grep -q "ProtectHome=true\|ProtectHome=yes\|ProtectHome=read-only\|ProtectHome=tmpfs"; then
            score=$((score + 1))
        fi

        # NoNewPrivileges
        if echo "$props" | grep -q "NoNewPrivileges=yes"; then
            score=$((score + 1))
        fi

        # PrivateTmp
        if echo "$props" | grep -q "PrivateTmp=yes"; then
            score=$((score + 1))
        fi

        # CapabilityBoundingSet (non-empty and not full set)
        local capbound
        capbound=$(echo "$props" | grep "^CapabilityBoundingSet=" | cut -d= -f2-)
        if [[ -n "$capbound" ]] && [[ "$capbound" != "" ]]; then
            # A restricted bounding set is fewer than the full set
            local cap_count
            cap_count=$(echo "$capbound" | tr ' ' '\n' | grep -c "." || true)
            if [[ "$cap_count" -gt 0 ]] && [[ "$cap_count" -lt 40 ]]; then
                score=$((score + 1))
            fi
        fi

        if [[ "$score" -ge 3 ]]; then
            hardened_count=$((hardened_count + 1))
        else
            unhardened_count=$((unhardened_count + 1))
            if [[ -n "$unhardened_list" ]]; then
                unhardened_list+=", "
            fi
            # Strip .service suffix for brevity
            unhardened_list+="${svc%.service}"
        fi
    done <<< "$services"

    local total=$((hardened_count + unhardened_count))

    if [[ "$unhardened_count" -eq 0 ]]; then
        result_pass "All running services have hardening directives" \
            "${hardened_count} service(s) checked"
    elif [[ "$unhardened_count" -le 3 ]]; then
        result_warn "Some services lack hardening directives" \
            "${unhardened_count}/${total} unhardened: ${unhardened_list}" \
            "Add ProtectSystem, NoNewPrivileges, PrivateTmp to unit files"
    else
        result_fail "Many services lack hardening directives" \
            "${unhardened_count}/${total} unhardened" \
            "Review and add systemd sandboxing directives to service unit files"
    fi

    # Individual directive coverage
    for dir in "${directives[@]}"; do
        local enabled_count=0
        while IFS= read -r svc; do
            [[ -z "$svc" ]] && continue
            local val
            val=$(systemctl show "$svc" --no-pager --property="$dir" 2>/dev/null \
                | cut -d= -f2- || true)
            case "$dir" in
                ProtectSystem)
                    [[ "$val" == "strict" || "$val" == "full" || "$val" == "true" || "$val" == "yes" ]] && \
                        enabled_count=$((enabled_count + 1))
                    ;;
                ProtectHome)
                    [[ "$val" == "true" || "$val" == "yes" || "$val" == "read-only" || "$val" == "tmpfs" ]] && \
                        enabled_count=$((enabled_count + 1))
                    ;;
                NoNewPrivileges|PrivateTmp)
                    [[ "$val" == "yes" ]] && enabled_count=$((enabled_count + 1))
                    ;;
                CapabilityBoundingSet)
                    if [[ -n "$val" ]]; then
                        local cnt
                        cnt=$(echo "$val" | tr ' ' '\n' | grep -c "." || true)
                        [[ "$cnt" -gt 0 && "$cnt" -lt 40 ]] && enabled_count=$((enabled_count + 1))
                    fi
                    ;;
            esac
        done <<< "$services"

        local pct=0
        [[ "$total" -gt 0 ]] && pct=$((enabled_count * 100 / total))

        if [[ "$pct" -ge 80 ]]; then
            result_pass "systemd ${dir} coverage" "${pct}% of services (${enabled_count}/${total})"
        elif [[ "$pct" -ge 40 ]]; then
            result_warn "systemd ${dir} coverage" "${pct}% of services (${enabled_count}/${total})" \
                "Enable ${dir} in more service unit files"
        else
            result_fail "systemd ${dir} coverage low" "${pct}% of services (${enabled_count}/${total})" \
                "Enable ${dir} in service unit files for defense in depth"
        fi
    done
}

# ---------------------------------------------------------------------------
# Check for services running as root without hardening
# ---------------------------------------------------------------------------
_check_root_services_without_hardening() {
    if ! command -v systemctl &>/dev/null; then
        return
    fi

    local root_unhardened=0
    local root_unhardened_list=""

    local services
    services=$(systemctl list-units --type=service --state=running --no-legend --no-pager 2>/dev/null \
        | awk '{print $1}' | head -50)

    while IFS= read -r svc; do
        [[ -z "$svc" ]] && continue

        local props
        props=$(systemctl show "$svc" --no-pager \
            --property=User,NoNewPrivileges,ProtectSystem 2>/dev/null || true)
        [[ -z "$props" ]] && continue

        # Check if running as root (User is empty or root)
        local user
        user=$(echo "$props" | grep "^User=" | cut -d= -f2-)
        if [[ -z "$user" || "$user" == "root" ]]; then
            # Check if it has at least basic hardening
            local nnp
            nnp=$(echo "$props" | grep "^NoNewPrivileges=" | cut -d= -f2-)
            local ps
            ps=$(echo "$props" | grep "^ProtectSystem=" | cut -d= -f2-)

            if [[ "$nnp" != "yes" ]] && [[ "$ps" != "strict" && "$ps" != "full" && "$ps" != "true" && "$ps" != "yes" ]]; then
                root_unhardened=$((root_unhardened + 1))
                if [[ -n "$root_unhardened_list" ]]; then
                    root_unhardened_list+=", "
                fi
                root_unhardened_list+="${svc%.service}"
            fi
        fi
    done <<< "$services"

    if [[ "$root_unhardened" -eq 0 ]]; then
        result_pass "No root services without hardening"
    elif [[ "$root_unhardened" -le 3 ]]; then
        result_warn "Root services without hardening" \
            "${root_unhardened} service(s): ${root_unhardened_list}" \
            "Add NoNewPrivileges=yes and ProtectSystem=strict to root service units"
    else
        result_fail "Many root services without hardening" \
            "${root_unhardened} service(s) running as root without sandboxing" \
            "Audit root services and add systemd security directives or run as non-root user"
    fi
}

# ---------------------------------------------------------------------------
# Check for enabled but unnecessary services
# ---------------------------------------------------------------------------
_check_unnecessary_services() {
    if ! command -v systemctl &>/dev/null; then
        return
    fi

    # Common services that are often unnecessary on embedded/edge devices
    local unnecessary_services=(
        "avahi-daemon.service"
        "cups.service"
        "cups-browsed.service"
        "bluetooth.service"
        "ModemManager.service"
        "accounts-daemon.service"
        "whoopsie.service"
        "apport.service"
        "kerneloops.service"
    )

    local found_unnecessary=0
    local found_list=""

    for svc in "${unnecessary_services[@]}"; do
        local state
        state=$(systemctl is-enabled "$svc" 2>/dev/null || true)
        if [[ "$state" == "enabled" ]]; then
            found_unnecessary=$((found_unnecessary + 1))
            if [[ -n "$found_list" ]]; then
                found_list+=", "
            fi
            found_list+="${svc%.service}"
        fi
    done

    if [[ "$found_unnecessary" -eq 0 ]]; then
        result_pass "No common unnecessary services enabled"
    elif [[ "$found_unnecessary" -le 2 ]]; then
        result_warn "Unnecessary services enabled" \
            "${found_unnecessary}: ${found_list}" \
            "Disable unnecessary services: systemctl disable --now <service>"
    else
        result_fail "Multiple unnecessary services enabled" \
            "${found_unnecessary}: ${found_list}" \
            "Disable unnecessary services to reduce attack surface: systemctl disable --now <service>"
    fi
}
