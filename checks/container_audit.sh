#!/usr/bin/env bash
# edge-hardener — Container security audit module
# Copyright (c) 2026 isecwire GmbH. MIT License.
#
# Sourced by edge_hardener.sh. Expects result_pass/result_fail/result_warn
# functions to be available in the caller's scope.

run_container_audit() {
    _check_container_runtime
    _check_privileged_containers
    _check_container_capabilities
    _check_seccomp_profiles
    _check_apparmor_selinux
    _check_docker_socket
    _check_container_images
    _check_container_networking
}

# ---------------------------------------------------------------------------
# Container runtime detection
# ---------------------------------------------------------------------------
_check_container_runtime() {
    local found_runtime=0

    if command -v docker &>/dev/null; then
        local docker_ver
        docker_ver=$(docker --version 2>/dev/null || echo "unknown")
        result_pass "Docker installed" "$docker_ver"
        found_runtime=1

        # Docker daemon configuration
        if [[ -f /etc/docker/daemon.json ]]; then
            result_pass "Docker daemon.json present"
            # Check for userns-remap
            if grep -q '"userns-remap"' /etc/docker/daemon.json 2>/dev/null; then
                result_pass "Docker user namespace remapping configured" "CIS-DK-2.8"
            else
                result_warn "Docker user namespace remapping not configured" \
                    "Containers run as host UID 0" \
                    "Enable userns-remap in /etc/docker/daemon.json"
            fi
            # Check for live-restore
            if grep -q '"live-restore"' /etc/docker/daemon.json 2>/dev/null; then
                result_pass "Docker live-restore configured"
            fi
            # Check for no-new-privileges
            if grep -q '"no-new-privileges"' /etc/docker/daemon.json 2>/dev/null; then
                result_pass "Docker no-new-privileges default set" "CIS-DK-2.17"
            else
                result_warn "Docker no-new-privileges not set as default" "" \
                    "Add {\"no-new-privileges\": true} to /etc/docker/daemon.json"
            fi
        else
            result_warn "Docker daemon.json not found" \
                "Cannot audit Docker daemon security settings" \
                "Create /etc/docker/daemon.json with hardened settings"
        fi
    fi

    if command -v podman &>/dev/null; then
        local podman_ver
        podman_ver=$(podman --version 2>/dev/null || echo "unknown")
        result_pass "Podman installed" "$podman_ver"
        found_runtime=1

        # Podman is rootless by default — check if running rootless
        if podman info --format '{{.Host.Security.Rootless}}' 2>/dev/null | grep -q "true"; then
            result_pass "Podman running in rootless mode" "CIS best practice"
        fi
    fi

    if command -v containerd &>/dev/null; then
        result_pass "containerd installed"
        found_runtime=1
    fi

    if [[ "$found_runtime" -eq 0 ]]; then
        result_pass "No container runtime detected" "N/A for this device"
        return
    fi
}

# ---------------------------------------------------------------------------
# Privileged containers
# ---------------------------------------------------------------------------
_check_privileged_containers() {
    if ! command -v docker &>/dev/null; then
        return
    fi

    local containers
    containers=$(docker ps --quiet 2>/dev/null || true)
    if [[ -z "$containers" ]]; then
        result_pass "No running Docker containers"
        return
    fi

    local privileged_count=0
    local total_count=0
    while IFS= read -r cid; do
        [[ -z "$cid" ]] && continue
        ((total_count++)) || true
        local is_priv
        is_priv=$(docker inspect --format '{{.HostConfig.Privileged}}' "$cid" 2>/dev/null || echo "false")
        if [[ "$is_priv" == "true" ]]; then
            local cname
            cname=$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's/^\///')
            result_fail "Privileged container: ${cname:-$cid}" "CIS-DK-5.4 — Full host access" \
                "Remove --privileged flag and use specific capabilities instead"
            ((privileged_count++)) || true
        fi
    done <<< "$containers"

    if [[ "$privileged_count" -eq 0 ]]; then
        result_pass "No privileged containers running" "${total_count} container(s) checked"
    fi
}

# ---------------------------------------------------------------------------
# Container capabilities
# ---------------------------------------------------------------------------
_check_container_capabilities() {
    if ! command -v docker &>/dev/null; then
        return
    fi

    local containers
    containers=$(docker ps --quiet 2>/dev/null || true)
    [[ -z "$containers" ]] && return

    # Dangerous capabilities that should be dropped
    local dangerous_caps=("NET_ADMIN" "SYS_ADMIN" "SYS_PTRACE" "SYS_RAWIO" "SYS_MODULE" "DAC_OVERRIDE")

    while IFS= read -r cid; do
        [[ -z "$cid" ]] && continue
        local cname
        cname=$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's/^\///')
        local cap_add
        cap_add=$(docker inspect --format '{{.HostConfig.CapAdd}}' "$cid" 2>/dev/null || echo "[]")

        for cap in "${dangerous_caps[@]}"; do
            if echo "$cap_add" | grep -q "$cap"; then
                result_warn "Container ${cname:-$cid} has ${cap} capability" \
                    "CIS-DK-5.3 — Excessive capability" \
                    "Remove ${cap} capability unless strictly required"
            fi
        done

        # Check if capabilities are dropped
        local cap_drop
        cap_drop=$(docker inspect --format '{{.HostConfig.CapDrop}}' "$cid" 2>/dev/null || echo "[]")
        if [[ "$cap_drop" == "[]" ]] || [[ "$cap_drop" == "<no value>" ]]; then
            result_warn "Container ${cname:-$cid} does not drop capabilities" \
                "CIS-DK-5.3" \
                "Use --cap-drop=ALL and add only required capabilities"
        fi
    done <<< "$containers"
}

# ---------------------------------------------------------------------------
# Seccomp profiles
# ---------------------------------------------------------------------------
_check_seccomp_profiles() {
    if ! command -v docker &>/dev/null; then
        return
    fi

    local containers
    containers=$(docker ps --quiet 2>/dev/null || true)
    [[ -z "$containers" ]] && return

    local unconfined=0
    while IFS= read -r cid; do
        [[ -z "$cid" ]] && continue
        local seccomp
        seccomp=$(docker inspect --format '{{.HostConfig.SecurityOpt}}' "$cid" 2>/dev/null || echo "[]")
        if echo "$seccomp" | grep -q "seccomp=unconfined"; then
            local cname
            cname=$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's/^\///')
            result_fail "Container ${cname:-$cid} runs with seccomp=unconfined" \
                "CIS-DK-5.2 — All syscalls allowed" \
                "Remove seccomp=unconfined and use default or custom profile"
            ((unconfined++)) || true
        fi
    done <<< "$containers"

    if [[ "$unconfined" -eq 0 ]] && [[ -n "$containers" ]]; then
        result_pass "No containers with seccomp disabled" "CIS-DK-5.2"
    fi
}

# ---------------------------------------------------------------------------
# AppArmor / SELinux for containers
# ---------------------------------------------------------------------------
_check_apparmor_selinux() {
    # Check host-level MAC
    if [[ -d /sys/kernel/security/apparmor ]]; then
        result_pass "AppArmor available on host"

        if command -v docker &>/dev/null; then
            local containers
            containers=$(docker ps --quiet 2>/dev/null || true)
            if [[ -n "$containers" ]]; then
                local no_profile=0
                while IFS= read -r cid; do
                    [[ -z "$cid" ]] && continue
                    local profile
                    profile=$(docker inspect --format '{{.AppArmorProfile}}' "$cid" 2>/dev/null || echo "")
                    if [[ -z "$profile" ]] || [[ "$profile" == "unconfined" ]]; then
                        ((no_profile++)) || true
                    fi
                done <<< "$containers"

                if [[ "$no_profile" -gt 0 ]]; then
                    result_warn "Containers without AppArmor profile" \
                        "${no_profile} container(s) unconfined" \
                        "Apply AppArmor profiles to all containers"
                else
                    result_pass "All containers have AppArmor profiles"
                fi
            fi
        fi
    elif [[ -d /sys/fs/selinux ]]; then
        local selinux_mode
        selinux_mode=$(getenforce 2>/dev/null || echo "unknown")
        if [[ "$selinux_mode" == "Enforcing" ]]; then
            result_pass "SELinux enforcing on host"
        elif [[ "$selinux_mode" == "Permissive" ]]; then
            result_warn "SELinux in permissive mode" "" \
                "Set SELinux to enforcing: setenforce 1"
        else
            result_warn "SELinux status unknown" "$selinux_mode"
        fi
    else
        result_warn "No MAC system detected" "Neither AppArmor nor SELinux active" \
            "Enable AppArmor or SELinux for mandatory access control"
    fi
}

# ---------------------------------------------------------------------------
# Docker socket exposure
# ---------------------------------------------------------------------------
_check_docker_socket() {
    # Check if Docker socket is world-readable
    if [[ -S /var/run/docker.sock ]]; then
        local sock_perms
        sock_perms=$(stat -c "%a" /var/run/docker.sock 2>/dev/null || echo "unknown")
        if [[ "$sock_perms" == "660" ]] || [[ "$sock_perms" == "600" ]]; then
            result_pass "Docker socket permissions" "mode ${sock_perms}"
        else
            result_fail "Docker socket permissions too open" "mode ${sock_perms}" \
                "Set permissions: chmod 660 /var/run/docker.sock"
        fi

        # Check if socket is mounted into any container
        local containers
        containers=$(docker ps --quiet 2>/dev/null || true)
        if [[ -n "$containers" ]]; then
            while IFS= read -r cid; do
                [[ -z "$cid" ]] && continue
                local mounts
                mounts=$(docker inspect --format '{{range .Mounts}}{{.Source}} {{end}}' "$cid" 2>/dev/null || true)
                if echo "$mounts" | grep -q "docker.sock"; then
                    local cname
                    cname=$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's/^\///')
                    result_fail "Docker socket mounted in container: ${cname:-$cid}" \
                        "CIS-DK-5.31 — Container escape risk" \
                        "Do not mount Docker socket inside containers"
                fi
            done <<< "$containers"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Container image audit
# ---------------------------------------------------------------------------
_check_container_images() {
    if ! command -v docker &>/dev/null; then
        return
    fi

    local containers
    containers=$(docker ps --quiet 2>/dev/null || true)
    [[ -z "$containers" ]] && return

    while IFS= read -r cid; do
        [[ -z "$cid" ]] && continue
        local image
        image=$(docker inspect --format '{{.Config.Image}}' "$cid" 2>/dev/null || echo "unknown")
        # Check for :latest tag
        if [[ "$image" == *":latest" ]] || [[ "$image" != *":"* ]]; then
            local cname
            cname=$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's/^\///')
            result_warn "Container ${cname:-$cid} uses :latest tag" \
                "Image: ${image}" \
                "Pin container images to specific version tags or digests"
        fi
    done <<< "$containers"

    # Check for running as root inside containers
    while IFS= read -r cid; do
        [[ -z "$cid" ]] && continue
        local user
        user=$(docker inspect --format '{{.Config.User}}' "$cid" 2>/dev/null || echo "")
        if [[ -z "$user" ]] || [[ "$user" == "0" ]] || [[ "$user" == "root" ]]; then
            local cname
            cname=$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's/^\///')
            result_warn "Container ${cname:-$cid} runs as root" \
                "CIS-DK-4.1" \
                "Set USER directive in Dockerfile or use --user flag"
        fi
    done <<< "$containers"
}

# ---------------------------------------------------------------------------
# Container networking
# ---------------------------------------------------------------------------
_check_container_networking() {
    if ! command -v docker &>/dev/null; then
        return
    fi

    local containers
    containers=$(docker ps --quiet 2>/dev/null || true)
    [[ -z "$containers" ]] && return

    while IFS= read -r cid; do
        [[ -z "$cid" ]] && continue
        local net_mode
        net_mode=$(docker inspect --format '{{.HostConfig.NetworkMode}}' "$cid" 2>/dev/null || echo "")
        if [[ "$net_mode" == "host" ]]; then
            local cname
            cname=$(docker inspect --format '{{.Name}}' "$cid" 2>/dev/null | sed 's/^\///')
            result_warn "Container ${cname:-$cid} uses host network" \
                "CIS-DK-5.9 — No network isolation" \
                "Use bridge or overlay networking instead of --net=host"
        fi
    done <<< "$containers"
}
