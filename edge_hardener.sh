#!/usr/bin/env bash
# edge-hardener — Embedded Linux security hardening auditor
# Copyright (c) 2026 isecwire GmbH. MIT License.
#
# Audits edge gateways and IoT devices for common security misconfigurations.
# Run as root on the target device for full coverage.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION="2.2.0"

# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# Box-drawing characters (BOX_BL/BOX_BR reserved for future layouts and
# cleared by the test harness in tests/test_edge_hardener.sh)
BOX_TL='\xe2\x94\x8c'
BOX_TR='\xe2\x94\x90'
# shellcheck disable=SC2034
BOX_BL='\xe2\x94\x94'
# shellcheck disable=SC2034
BOX_BR='\xe2\x94\x98'
BOX_H='\xe2\x94\x80'
BOX_V='\xe2\x94\x82'

# ---------------------------------------------------------------------------
# Global state
# ---------------------------------------------------------------------------
JSON_RESULTS=()
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0
TOTAL_COUNT=0
CURRENT_CHECK=0
TOTAL_CHECKS=0
CURRENT_CATEGORY=""

# Fix mode state
FIX_MODE=0
FIX_SCRIPT_FILE=""
FIX_COMMANDS=()
UNDO_COMMANDS=()

# Policy engine state
POLICY_FILE=""
POLICY_NAME=""
declare -A POLICY_CHECKS
declare -a POLICY_ENFORCED_PATTERNS=()
declare -a POLICY_ENFORCED_REQUIRE=()
declare -a POLICY_ENFORCED_REASON=()
POLICY_MAX_FAIL=999
POLICY_MAX_WARN=999
POLICY_MIN_PASS_PCT=0

# Baseline comparison
BASELINE_FILE=""

# Output format
OUTPUT_FORMAT="text"

# Check filtering
INCLUDE_CHECKS=""
EXCLUDE_CHECKS=""

# All check categories (in order) — reference documentation for --checks /
# --exclude filters; read by policy loaders at runtime.
# shellcheck disable=SC2034
ALL_CATEGORIES="secure_boot kernel_hardening dm_verity debug_interfaces network_exposure filesystem_permissions ssh_hardening firewall module_loading core_dumps container_audit crypto_audit supply_chain_audit bootloader_audit systemd_audit usb_audit"

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
banner() {
    echo ""
    echo -e "${CYAN}${BOLD}"
    echo '    _____ ____   _____ _____  __        _____ ____  _____'
    echo '   |_   _/ ___| | ____/ ___| \ \      / /_ _|  _ \| ____|'
    echo '     | | \___ \ |  _|| |      \ \ /\ / / | || |_) |  _|'
    echo '     | |  ___) || |__| |___    \ V  V /  | ||  _ <| |___'
    echo '     |_| |____/ |_____\____|    \_/\_/  |___|_| \_\_____|'
    echo -e "${NC}"
    echo -e "    ${BOLD}edge-hardener${NC} v${VERSION} ${DIM}— Embedded Linux Security Auditor${NC}"
    if [[ -n "$POLICY_NAME" ]]; then
        echo -e "    ${MAGENTA}Policy: ${POLICY_NAME}${NC}"
    fi
    echo ""
    _draw_box_line "Target" "$(hostname) ($(uname -m))"
    _draw_box_line "Kernel" "$(uname -r)"
    _draw_box_line "Date  " "$(date -Iseconds)"
    if [[ "$EUID" -eq 0 ]]; then
        _draw_box_line "User  " "root"
    else
        _draw_box_line "User  " "$(whoami) ${YELLOW}(limited checks)${NC}"
    fi
    echo ""
}

_draw_box_line() {
    echo -e "    ${DIM}${BOX_V}${NC} ${BOLD}$1${NC} : $2"
}

_category_header() {
    local title="$1"
    local width=60
    local pad_len=$(( width - ${#title} - 4 ))
    [[ "$pad_len" -lt 2 ]] && pad_len=2
    local padding=""
    for ((i=0; i<pad_len; i++)); do
        padding+=$(printf '\xe2\x94\x80')
    done
    echo ""
    echo -e "  ${BOLD}${CYAN}${BOX_TL}${BOX_H}${BOX_H}${NC} ${BOLD}${title}${NC} ${CYAN}${padding}${BOX_TR}${NC}"
    CURRENT_CATEGORY="$title"
}

_json_escape() {
    local s="$1"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    echo -n "$s"
}

_progress_prefix() {
    if [[ "$TOTAL_CHECKS" -gt 0 ]]; then
        ((CURRENT_CHECK++)) || true
        echo -e "  ${DIM}[${CURRENT_CHECK}/${TOTAL_CHECKS}]${NC} "
    else
        echo "  "
    fi
}

result_pass() {
    local check="$1" detail="${2:-}" cis_id="${3:-}"
    local prefix
    prefix=$(_progress_prefix)
    local cis_tag=""
    [[ -n "$cis_id" ]] && cis_tag=" ${DIM}(${cis_id})${NC}"
    echo -e "${prefix}[${GREEN}PASS${NC}] ${check}${detail:+ — $detail}${cis_tag}"

    local esc_detail; esc_detail=$(_json_escape "$detail")
    local esc_check; esc_check=$(_json_escape "$check")
    local json="{\"check\":\"${esc_check}\",\"status\":\"PASS\",\"detail\":\"${esc_detail}\",\"category\":\"${CURRENT_CATEGORY}\""
    [[ -n "$cis_id" ]] && json+=",\"cis_id\":\"${cis_id}\""
    json+="}"
    JSON_RESULTS+=("$json")
    ((PASS_COUNT++)) || true
    ((TOTAL_COUNT++)) || true
}

result_fail() {
    local check="$1" detail="${2:-}" remediation="${3:-}" cis_id="${4:-}"
    local prefix
    prefix=$(_progress_prefix)
    local cis_tag=""
    [[ -n "$cis_id" ]] && cis_tag=" ${DIM}(${cis_id})${NC}"
    echo -e "${prefix}[${RED}FAIL${NC}] ${check}${detail:+ — $detail}${cis_tag}"

    local esc_detail; esc_detail=$(_json_escape "$detail")
    local esc_check; esc_check=$(_json_escape "$check")
    local esc_rem; esc_rem=$(_json_escape "$remediation")
    local json="{\"check\":\"${esc_check}\",\"status\":\"FAIL\",\"detail\":\"${esc_detail}\",\"category\":\"${CURRENT_CATEGORY}\""
    [[ -n "$remediation" ]] && json+=",\"remediation\":\"${esc_rem}\""
    [[ -n "$cis_id" ]] && json+=",\"cis_id\":\"${cis_id}\""
    json+="}"
    JSON_RESULTS+=("$json")
    ((FAIL_COUNT++)) || true
    ((TOTAL_COUNT++)) || true
}

result_warn() {
    local check="$1" detail="${2:-}" remediation="${3:-}" cis_id="${4:-}"
    local prefix
    prefix=$(_progress_prefix)
    local cis_tag=""
    [[ -n "$cis_id" ]] && cis_tag=" ${DIM}(${cis_id})${NC}"
    echo -e "${prefix}[${YELLOW}WARN${NC}] ${check}${detail:+ — $detail}${cis_tag}"

    local esc_detail; esc_detail=$(_json_escape "$detail")
    local esc_check; esc_check=$(_json_escape "$check")
    local esc_rem; esc_rem=$(_json_escape "$remediation")
    local json="{\"check\":\"${esc_check}\",\"status\":\"WARN\",\"detail\":\"${esc_detail}\",\"category\":\"${CURRENT_CATEGORY}\""
    [[ -n "$remediation" ]] && json+=",\"remediation\":\"${esc_rem}\""
    [[ -n "$cis_id" ]] && json+=",\"cis_id\":\"${cis_id}\""
    json+="}"
    JSON_RESULTS+=("$json")
    ((WARN_COUNT++)) || true
    ((TOTAL_COUNT++)) || true
}

section() {
    _category_header "$1"
}

# ---------------------------------------------------------------------------
# Fix / remediation helpers
# ---------------------------------------------------------------------------
register_fix() {
    local fix_cmd="$1" undo_cmd="${2:-}"
    if [[ "$FIX_MODE" -eq 1 ]]; then
        FIX_COMMANDS+=("$fix_cmd")
        [[ -n "$undo_cmd" ]] && UNDO_COMMANDS+=("$undo_cmd")
    fi
}

apply_fixes() {
    if [[ "${#FIX_COMMANDS[@]}" -eq 0 ]]; then
        echo -e "  ${GREEN}No fixes to apply.${NC}"
        return
    fi

    if [[ -n "$FIX_SCRIPT_FILE" ]]; then
        # Write fix script instead of applying
        {
            echo "#!/usr/bin/env bash"
            echo "# edge-hardener auto-generated fix script"
            echo "# Generated: $(date -Iseconds)"
            echo "# Host: $(hostname)"
            echo "# Policy: ${POLICY_NAME:-none}"
            echo ""
            echo "set -euo pipefail"
            echo ""
            echo "echo 'Applying ${#FIX_COMMANDS[@]} fix(es)...'"
            echo ""
            for cmd in "${FIX_COMMANDS[@]}"; do
                echo "echo \"Applying: ${cmd}\""
                echo "$cmd"
                echo ""
            done
            echo "echo 'All fixes applied.'"
        } > "$FIX_SCRIPT_FILE"
        chmod +x "$FIX_SCRIPT_FILE"
        echo -e "  ${BLUE}Fix script written to: ${FIX_SCRIPT_FILE}${NC}"
        echo -e "  ${DIM}${#FIX_COMMANDS[@]} fix(es) in script${NC}"

        # Write undo script
        local undo_file="${FIX_SCRIPT_FILE%.sh}-undo.sh"
        if [[ "${#UNDO_COMMANDS[@]}" -gt 0 ]]; then
            {
                echo "#!/usr/bin/env bash"
                echo "# edge-hardener auto-generated UNDO script"
                echo "# Reverses fixes from: ${FIX_SCRIPT_FILE}"
                echo "# Generated: $(date -Iseconds)"
                echo ""
                echo "set -euo pipefail"
                echo ""
                echo "echo 'Reverting ${#UNDO_COMMANDS[@]} fix(es)...'"
                echo ""
                for cmd in "${UNDO_COMMANDS[@]}"; do
                    echo "echo \"Reverting: ${cmd}\""
                    echo "$cmd"
                    echo ""
                done
                echo "echo 'All fixes reverted.'"
            } > "$undo_file"
            chmod +x "$undo_file"
            echo -e "  ${BLUE}Undo script written to: ${undo_file}${NC}"
        fi
    else
        # Apply fixes directly
        echo ""
        echo -e "  ${BOLD}Applying ${#FIX_COMMANDS[@]} fix(es)...${NC}"
        for cmd in "${FIX_COMMANDS[@]}"; do
            echo -e "  ${DIM}$ ${cmd}${NC}"
            if eval "$cmd" 2>/dev/null; then
                echo -e "  ${GREEN}OK${NC}"
            else
                echo -e "  ${RED}Failed${NC}"
            fi
        done
    fi
}

# ---------------------------------------------------------------------------
# Policy engine
# ---------------------------------------------------------------------------
load_policy() {
    local policy_file="$1"
    if [[ ! -f "$policy_file" ]]; then
        echo "Error: Policy file not found: ${policy_file}" >&2
        exit 1
    fi

    # Simple YAML parser (no external dependencies)
    local in_checks=0
    local in_enforced=0
    local in_thresholds=0
    local in_enforced_entry=0
    local current_pattern="" current_require="" current_reason=""

    while IFS= read -r line; do
        # Strip comments
        line="${line%%#*}"
        # Skip empty lines
        [[ -z "${line// /}" ]] && continue

        # Top-level keys
        if [[ "$line" =~ ^name:\ *\"(.*)\" ]]; then
            POLICY_NAME="${BASH_REMATCH[1]}"
            in_checks=0; in_enforced=0; in_thresholds=0; in_enforced_entry=0
            continue
        fi
        if [[ "$line" =~ ^description: ]]; then
            in_checks=0; in_enforced=0; in_thresholds=0; in_enforced_entry=0
            continue
        fi
        if [[ "$line" =~ ^version: ]] || [[ "$line" =~ ^standard: ]]; then
            continue
        fi

        if [[ "$line" =~ ^checks: ]]; then
            in_checks=1; in_enforced=0; in_thresholds=0; in_enforced_entry=0
            continue
        fi
        if [[ "$line" =~ ^enforced: ]]; then
            in_checks=0; in_enforced=1; in_thresholds=0; in_enforced_entry=0
            continue
        fi
        if [[ "$line" =~ ^thresholds: ]]; then
            in_checks=0; in_enforced=0; in_thresholds=1; in_enforced_entry=0
            continue
        fi

        # Parse checks section
        if [[ "$in_checks" -eq 1 ]]; then
            if [[ "$line" =~ ^[[:space:]]+([a-z_]+):\ *(true|false) ]]; then
                POLICY_CHECKS["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
            fi
            continue
        fi

        # Parse enforced section
        if [[ "$in_enforced" -eq 1 ]]; then
            if [[ "$line" =~ ^[[:space:]]*-\ *pattern:\ *\"(.*)\" ]]; then
                # Save previous entry if exists
                if [[ -n "$current_pattern" ]]; then
                    POLICY_ENFORCED_PATTERNS+=("$current_pattern")
                    POLICY_ENFORCED_REQUIRE+=("$current_require")
                    POLICY_ENFORCED_REASON+=("$current_reason")
                fi
                current_pattern="${BASH_REMATCH[1]}"
                current_require=""
                current_reason=""
                in_enforced_entry=1
                continue
            fi
            if [[ "$in_enforced_entry" -eq 1 ]]; then
                if [[ "$line" =~ ^[[:space:]]+require:\ *\"(.*)\" ]]; then
                    current_require="${BASH_REMATCH[1]}"
                fi
                if [[ "$line" =~ ^[[:space:]]+reason:\ *\"(.*)\" ]]; then
                    current_reason="${BASH_REMATCH[1]}"
                fi
            fi
            continue
        fi

        # Parse thresholds
        if [[ "$in_thresholds" -eq 1 ]]; then
            if [[ "$line" =~ ^[[:space:]]+max_fail:\ *([0-9]+) ]]; then
                POLICY_MAX_FAIL="${BASH_REMATCH[1]}"
            fi
            if [[ "$line" =~ ^[[:space:]]+max_warn:\ *([0-9]+) ]]; then
                POLICY_MAX_WARN="${BASH_REMATCH[1]}"
            fi
            if [[ "$line" =~ ^[[:space:]]+min_pass_percent:\ *([0-9]+) ]]; then
                POLICY_MIN_PASS_PCT="${BASH_REMATCH[1]}"
            fi
            continue
        fi
    done < "$policy_file"

    # Save last enforced entry
    if [[ -n "$current_pattern" ]]; then
        POLICY_ENFORCED_PATTERNS+=("$current_pattern")
        POLICY_ENFORCED_REQUIRE+=("$current_require")
        POLICY_ENFORCED_REASON+=("$current_reason")
    fi
}

is_check_enabled() {
    local check_name="$1"

    # If --checks is specified, only run those
    if [[ -n "$INCLUDE_CHECKS" ]]; then
        if ! echo ",$INCLUDE_CHECKS," | grep -q ",$check_name,"; then
            return 1
        fi
    fi

    # If --exclude is specified, skip those
    if [[ -n "$EXCLUDE_CHECKS" ]]; then
        if echo ",$EXCLUDE_CHECKS," | grep -q ",$check_name,"; then
            return 1
        fi
    fi

    # Check policy
    if [[ -n "$POLICY_FILE" ]]; then
        local policy_val="${POLICY_CHECKS[$check_name]:-true}"
        if [[ "$policy_val" == "false" ]]; then
            return 1
        fi
    fi

    return 0
}

apply_policy_enforcement() {
    # After all checks, scan results and elevate WARN to FAIL per policy
    if [[ "${#POLICY_ENFORCED_PATTERNS[@]}" -eq 0 ]]; then
        return
    fi

    local new_results=()
    local policy_violations=0

    for result_json in "${JSON_RESULTS[@]}"; do
        local result_check=""
        local result_status=""
        # Extract check name and status from JSON
        if [[ "$result_json" =~ \"check\":\"([^\"]+)\" ]]; then
            result_check="${BASH_REMATCH[1]}"
        fi
        if [[ "$result_json" =~ \"status\":\"([^\"]+)\" ]]; then
            result_status="${BASH_REMATCH[1]}"
        fi

        local elevated=0
        for i in "${!POLICY_ENFORCED_PATTERNS[@]}"; do
            local pattern="${POLICY_ENFORCED_PATTERNS[$i]}"
            local require="${POLICY_ENFORCED_REQUIRE[$i]}"
            local reason="${POLICY_ENFORCED_REASON[$i]}"

            if echo "$result_check" | grep -qi "$pattern"; then
                if [[ "$require" == "PASS" ]] && [[ "$result_status" != "PASS" ]]; then
                    # Elevate to FAIL
                    local new_json="${result_json/\"status\":\"WARN\"/\"status\":\"FAIL\"}"
                    new_json="${new_json/\"status\":\"FAIL\"/\"status\":\"FAIL\"}"
                    # Add policy violation note
                    if [[ "$new_json" != *"policy_violation"* ]]; then
                        new_json="${new_json%\}},\"policy_violation\":\"${reason}\"}"
                    fi
                    new_results+=("$new_json")
                    elevated=1

                    if [[ "$result_status" == "WARN" ]]; then
                        # Adjust counters for WARN->FAIL elevation
                        ((WARN_COUNT--)) || true
                        ((FAIL_COUNT++)) || true
                        ((policy_violations++)) || true
                    fi
                    break
                fi
            fi
        done

        if [[ "$elevated" -eq 0 ]]; then
            new_results+=("$result_json")
        fi
    done

    JSON_RESULTS=("${new_results[@]}")

    if [[ "$policy_violations" -gt 0 ]]; then
        echo ""
        echo -e "  ${MAGENTA}${BOLD}Policy enforcement: ${policy_violations} warning(s) elevated to FAIL${NC}"
    fi
}

# ---------------------------------------------------------------------------
# Baseline comparison
# ---------------------------------------------------------------------------
compare_baseline() {
    local baseline_file="$1"
    if [[ ! -f "$baseline_file" ]]; then
        echo "Error: Baseline file not found: ${baseline_file}" >&2
        return
    fi

    echo ""
    echo -e "  ${BOLD}${CYAN}${BOX_TL}${BOX_H}${BOX_H}${NC} ${BOLD}Baseline Comparison${NC} ${CYAN}$(printf '%0.s\xe2\x94\x80' {1..38})${BOX_TR}${NC}"
    echo ""

    # Use python3 to compare JSON baselines
    python3 -c "
import json, sys

with open('${baseline_file}', 'r') as f:
    baseline = json.load(f)

# Build current results from stdin
current_json = sys.stdin.read()
current = json.loads(current_json)

baseline_checks = {r['check']: r['status'] for r in baseline.get('results', [])}
current_checks = {r['check']: r['status'] for r in current.get('results', [])}

new_findings = []
resolved = []
regressions = []
improved = []

for check, status in current_checks.items():
    if check not in baseline_checks:
        new_findings.append((check, status))
    elif baseline_checks[check] == 'PASS' and status in ('FAIL', 'WARN'):
        regressions.append((check, baseline_checks[check], status))
    elif baseline_checks[check] in ('FAIL', 'WARN') and status == 'PASS':
        improved.append((check, baseline_checks[check], status))

for check, status in baseline_checks.items():
    if check not in current_checks:
        resolved.append((check, status))

# Color codes
RED = '\033[0;31m'
GREEN = '\033[0;32m'
YELLOW = '\033[1;33m'
CYAN = '\033[0;36m'
NC = '\033[0m'
BOLD = '\033[1m'
DIM = '\033[2m'

bs = baseline.get('summary', {})
cs = current.get('summary', {})
print(f'  {DIM}Baseline:{NC} {baseline.get(\"timestamp\", \"unknown\")}')
print(f'  {DIM}Current: {NC} {current.get(\"timestamp\", \"unknown\")}')
print()

# Summary delta
def delta_str(cur, prev):
    d = cur - prev
    if d > 0:
        return f'+{d}'
    elif d < 0:
        return str(d)
    return '0'

print(f'  {BOLD}Summary Delta:{NC}')
print(f'    Total: {bs.get(\"total\",0)} -> {cs.get(\"total\",0)} ({delta_str(cs.get(\"total\",0), bs.get(\"total\",0))})')
print(f'    {GREEN}PASS{NC}: {bs.get(\"pass\",0)} -> {cs.get(\"pass\",0)} ({delta_str(cs.get(\"pass\",0), bs.get(\"pass\",0))})')
print(f'    {RED}FAIL{NC}: {bs.get(\"fail\",0)} -> {cs.get(\"fail\",0)} ({delta_str(cs.get(\"fail\",0), bs.get(\"fail\",0))})')
print(f'    {YELLOW}WARN{NC}: {bs.get(\"warn\",0)} -> {cs.get(\"warn\",0)} ({delta_str(cs.get(\"warn\",0), bs.get(\"warn\",0))})')
print()

if regressions:
    print(f'  {RED}{BOLD}Regressions ({len(regressions)}):{NC}')
    for check, old, new in regressions:
        print(f'    {RED}[-]{NC} {check}: {old} -> {new}')
    print()

if improved:
    print(f'  {GREEN}{BOLD}Improved ({len(improved)}):{NC}')
    for check, old, new in improved:
        print(f'    {GREEN}[+]{NC} {check}: {old} -> {new}')
    print()

if new_findings:
    print(f'  {CYAN}{BOLD}New findings ({len(new_findings)}):{NC}')
    for check, status in new_findings:
        color = RED if status == 'FAIL' else YELLOW if status == 'WARN' else GREEN
        print(f'    {color}[*]{NC} {check}: {status}')
    print()

if resolved:
    print(f'  {DIM}Removed checks ({len(resolved)}):{NC}')
    for check, status in resolved[:10]:
        print(f'    {DIM}[~] {check}: was {status}{NC}')
    if len(resolved) > 10:
        print(f'    {DIM}... and {len(resolved)-10} more{NC}')
    print()

if not regressions and not new_findings:
    print(f'  {GREEN}{BOLD}No regressions detected.{NC}')
    print()
" <<< "$(build_current_json)"
}

build_current_json() {
    local json="{"
    json+="\"hostname\":\"$(hostname)\","
    json+="\"kernel\":\"$(uname -r)\","
    json+="\"arch\":\"$(uname -m)\","
    json+="\"timestamp\":\"$(date -Iseconds)\","
    json+="\"version\":\"${VERSION}\","
    json+="\"schema_version\":\"2.2\","
    if [[ -n "$POLICY_NAME" ]]; then
        json+="\"policy\":\"${POLICY_NAME}\","
    fi
    json+="\"summary\":{\"total\":${TOTAL_COUNT},\"pass\":${PASS_COUNT},\"fail\":${FAIL_COUNT},\"warn\":${WARN_COUNT}},"
    json+="\"results\":["

    local first=1
    for r in "${JSON_RESULTS[@]}"; do
        [[ "$first" -eq 0 ]] && json+=","
        json+="$r"
        first=0
    done

    json+="]}"
    echo "$json"
}

# ---------------------------------------------------------------------------
# 1. Secure Boot
# ---------------------------------------------------------------------------
check_secure_boot() {
    section "Secure Boot"

    # EFI variables
    if [[ -d /sys/firmware/efi ]]; then
        result_pass "EFI firmware detected" "" "CIS 1.4.2"
    else
        result_warn "EFI firmware not detected" "System may use legacy BIOS — Secure Boot not applicable" \
            "Consider UEFI firmware for Secure Boot support" "CIS 1.4.2"
    fi

    # mokutil
    if command -v mokutil &>/dev/null; then
        local sb_state
        sb_state=$(mokutil --sb-state 2>/dev/null || echo "unknown")
        if echo "$sb_state" | grep -qi "enabled"; then
            result_pass "Secure Boot enabled" "$sb_state" "CIS 1.4.2"
        else
            result_fail "Secure Boot not enabled" "$sb_state" \
                "Enable Secure Boot in UEFI settings and enroll proper keys" "CIS 1.4.2"
        fi
    else
        result_warn "mokutil not installed" "Cannot verify Secure Boot state" \
            "Install mokutil: apt install mokutil / dnf install mokutil"
    fi
}

# ---------------------------------------------------------------------------
# 2. Kernel Hardening
# ---------------------------------------------------------------------------
check_kernel_hardening() {
    section "Kernel Hardening"

    # Source the detailed kernel audit if available
    if [[ -f "${SCRIPT_DIR}/checks/kernel_audit.sh" ]]; then
        source "${SCRIPT_DIR}/checks/kernel_audit.sh"
        run_kernel_audit
    else
        _kernel_hardening_inline
    fi
}

_kernel_hardening_inline() {
    # KASLR
    if grep -q "nokaslr" /proc/cmdline 2>/dev/null; then
        result_fail "KASLR disabled via boot params" "nokaslr found in /proc/cmdline" \
            "Remove nokaslr from kernel command line"
    else
        result_pass "KASLR not explicitly disabled"
    fi

    # CPU flags: SMEP / SMAP
    if grep -q "smep" /proc/cpuinfo 2>/dev/null; then
        result_pass "SMEP supported"
    else
        result_warn "SMEP not detected in CPU flags" "Supervisor Mode Execution Prevention unavailable"
    fi

    if grep -q "smap" /proc/cpuinfo 2>/dev/null; then
        result_pass "SMAP supported"
    else
        result_warn "SMAP not detected in CPU flags" "Supervisor Mode Access Prevention unavailable"
    fi

    # Kernel config checks
    local kconfig=""
    for cfg in /boot/config-"$(uname -r)" /proc/config.gz; do
        if [[ -f "$cfg" ]]; then
            kconfig="$cfg"
            break
        fi
    done

    if [[ -n "$kconfig" ]]; then
        local reader="cat"
        [[ "$kconfig" == *.gz ]] && reader="zcat"

        if $reader "$kconfig" 2>/dev/null | grep -q "CONFIG_STACKPROTECTOR_STRONG=y"; then
            result_pass "Stack protector strong enabled"
        elif $reader "$kconfig" 2>/dev/null | grep -q "CONFIG_STACKPROTECTOR=y"; then
            result_warn "Basic stack protector only" "STRONG variant recommended" \
                "Rebuild kernel with CONFIG_STACKPROTECTOR_STRONG=y"
        else
            result_fail "Stack protector not enabled" "" \
                "Rebuild kernel with CONFIG_STACKPROTECTOR_STRONG=y"
        fi
    else
        result_warn "Kernel config not found" "Cannot audit compile-time hardening options"
    fi
}

# ---------------------------------------------------------------------------
# 3. dm-verity
# ---------------------------------------------------------------------------
check_dm_verity() {
    section "dm-verity / Integrity"

    if command -v dmsetup &>/dev/null; then
        local verity_targets
        verity_targets=$(dmsetup table --target verity 2>/dev/null | head -5 || true)
        if [[ -n "$verity_targets" ]]; then
            result_pass "dm-verity targets active" "$(echo "$verity_targets" | wc -l) target(s)"
        else
            result_warn "No dm-verity targets found" "Root filesystem integrity not enforced" \
                "Configure dm-verity for read-only root partitions"
        fi
    else
        result_warn "dmsetup not installed" "Cannot check dm-verity status" \
            "Install device-mapper tools"
    fi

    if command -v veritysetup &>/dev/null; then
        result_pass "veritysetup available"
    else
        result_warn "veritysetup not installed" "" \
            "Install cryptsetup (includes veritysetup)"
    fi
}

# ---------------------------------------------------------------------------
# 4. Debug Interfaces
# ---------------------------------------------------------------------------
check_debug_interfaces() {
    section "Debug Interfaces"

    # Kernel debug params
    local debug_params=("kgdboc" "kdb" "debug" "earlyprintk")
    local cmdline
    cmdline=$(cat /proc/cmdline 2>/dev/null || echo "")
    for param in "${debug_params[@]}"; do
        if echo "$cmdline" | grep -qw "$param"; then
            result_fail "Debug kernel param active: ${param}" "Found in /proc/cmdline" \
                "Remove '${param}' from kernel command line in production"
            register_fix "# Manual: remove '${param}' from bootloader kernel cmdline"
        fi
    done

    # Check for debugfs mount
    if mount | grep -q debugfs 2>/dev/null; then
        result_warn "debugfs is mounted" "Exposes kernel internals" \
            "Unmount debugfs: umount /sys/kernel/debug" "CIS 1.1.22"
        register_fix "umount /sys/kernel/debug 2>/dev/null || true" \
            "mount -t debugfs debugfs /sys/kernel/debug"
    else
        result_pass "debugfs not mounted" "" "CIS 1.1.22"
    fi

    # JTAG / SWD exposure via sysfs GPIO
    local gpio_exposed=0
    if [[ -d /sys/class/gpio ]]; then
        local exported=0
        local gpio_entry
        for gpio_entry in /sys/class/gpio/gpio[0-9]*; do
            [[ -e "$gpio_entry" ]] && ((exported++))
        done
        if [[ "$exported" -gt 0 ]]; then
            result_warn "GPIO pins exported" "${exported} pin(s) via sysfs" \
                "Unexport unused GPIO pins to reduce JTAG/SWD attack surface"
            gpio_exposed=1
        fi
    fi
    if [[ "$gpio_exposed" -eq 0 ]]; then
        result_pass "No GPIO pins exported via sysfs"
    fi

    # kprobes
    if [[ -d /sys/kernel/debug/kprobes ]] || [[ -f /sys/kernel/kprobes/enabled ]]; then
        local kp_enabled
        kp_enabled=$(cat /sys/kernel/kprobes/enabled 2>/dev/null || echo "unknown")
        if [[ "$kp_enabled" == "1" ]]; then
            result_warn "kprobes enabled" "Can be used for runtime kernel instrumentation" \
                "Disable kprobes if not needed: echo 0 > /sys/kernel/kprobes/enabled"
            register_fix "echo 0 > /sys/kernel/kprobes/enabled" \
                "echo 1 > /sys/kernel/kprobes/enabled"
        fi
    fi
}

# ---------------------------------------------------------------------------
# 5. Network Exposure
# ---------------------------------------------------------------------------
check_network_exposure() {
    section "Network Exposure"

    if [[ -f "${SCRIPT_DIR}/checks/network_audit.sh" ]]; then
        source "${SCRIPT_DIR}/checks/network_audit.sh"
        run_network_audit
    else
        _network_exposure_inline
    fi
}

_network_exposure_inline() {
    if command -v ss &>/dev/null; then
        local listening
        listening=$(ss -tlnp 2>/dev/null | tail -n +2 || true)
        local count
        count=$(echo "$listening" | grep -c "LISTEN" || true)
        if [[ "$count" -gt 10 ]]; then
            result_warn "Many listening ports" "${count} TCP listeners detected" \
                "Disable unnecessary services to reduce attack surface"
        else
            result_pass "TCP listener count" "${count} port(s) open"
        fi

        # Flag common risky services
        if echo "$listening" | grep -q ":23 "; then
            result_fail "Telnet service detected (port 23)" "" \
                "Disable telnet and use SSH instead"
        fi
        if echo "$listening" | grep -q ":21 "; then
            result_warn "FTP service detected (port 21)" "" \
                "Replace FTP with SFTP or SCP"
        fi
    fi
}

# ---------------------------------------------------------------------------
# 6. Filesystem Permissions
# ---------------------------------------------------------------------------
check_filesystem_permissions() {
    section "Filesystem Permissions"

    if [[ -f "${SCRIPT_DIR}/checks/filesystem_audit.sh" ]]; then
        source "${SCRIPT_DIR}/checks/filesystem_audit.sh"
        run_filesystem_audit
    else
        _filesystem_permissions_inline
    fi
}

_filesystem_permissions_inline() {
    # World-writable directories (excluding standard tmpfs)
    local ww_dirs
    ww_dirs=$(find / -maxdepth 3 -type d -perm -0002 \
        ! -path "/tmp" ! -path "/tmp/*" \
        ! -path "/var/tmp" ! -path "/var/tmp/*" \
        ! -path "/dev/*" ! -path "/proc/*" ! -path "/sys/*" \
        ! -path "/run/*" 2>/dev/null | head -20 || true)
    local ww_count
    ww_count=$(echo "$ww_dirs" | grep -c "." || true)

    if [[ "$ww_count" -gt 0 ]]; then
        result_warn "World-writable directories found" "${ww_count} outside /tmp" \
            "Review and restrict permissions: chmod o-w <dir>"
    else
        result_pass "No unexpected world-writable directories"
    fi

    # SUID binaries
    local suid_bins
    suid_bins=$(find / -maxdepth 4 -type f -perm -4000 \
        ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null | head -30 || true)
    local suid_count
    suid_count=$(echo "$suid_bins" | grep -c "." || true)

    if [[ "$suid_count" -gt 15 ]]; then
        result_warn "High SUID binary count" "${suid_count} SUID binaries" \
            "Audit SUID binaries and remove unnecessary ones: chmod u-s <file>"
    else
        result_pass "SUID binary count" "${suid_count} found"
    fi
}

# ---------------------------------------------------------------------------
# 7. SSH Hardening
# ---------------------------------------------------------------------------
check_ssh_hardening() {
    section "SSH Configuration"

    local sshd_config="/etc/ssh/sshd_config"
    if [[ ! -f "$sshd_config" ]]; then
        result_warn "sshd_config not found" "SSH may not be installed"
        return
    fi

    # Concatenate main config and included drop-in files for a complete picture
    local full_config
    full_config=$(cat "$sshd_config" 2>/dev/null)
    # Also read drop-in configs
    for inc in /etc/ssh/sshd_config.d/*.conf; do
        [[ -f "$inc" ]] && full_config+=$'\n'"$(cat "$inc" 2>/dev/null)"
    done

    # PermitRootLogin
    local root_login
    root_login=$(echo "$full_config" | grep -i "^PermitRootLogin" | tail -1 | awk '{print $2}' || true)
    if [[ -z "$root_login" ]] || [[ "$root_login" == "yes" ]]; then
        result_fail "SSH PermitRootLogin" "${root_login:-yes (default)}" \
            "Set PermitRootLogin no in sshd_config" "CIS 5.2.10"
        register_fix \
            "sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config && systemctl reload sshd 2>/dev/null || true" \
            "sed -i 's/^PermitRootLogin no/PermitRootLogin yes/' /etc/ssh/sshd_config && systemctl reload sshd 2>/dev/null || true"
    elif [[ "$root_login" == "prohibit-password" ]] || [[ "$root_login" == "without-password" ]]; then
        result_warn "SSH PermitRootLogin" "$root_login — key-only root access" \
            "Consider PermitRootLogin no for maximum security" "CIS 5.2.10"
    else
        result_pass "SSH PermitRootLogin" "$root_login" "CIS 5.2.10"
    fi

    # PasswordAuthentication
    local pwd_auth
    pwd_auth=$(echo "$full_config" | grep -i "^PasswordAuthentication" | tail -1 | awk '{print $2}' || true)
    if [[ -z "$pwd_auth" ]] || [[ "$pwd_auth" == "yes" ]]; then
        result_fail "SSH PasswordAuthentication" "${pwd_auth:-yes (default)}" \
            "Set PasswordAuthentication no and use key-based auth" "CIS 5.2.12"
        register_fix \
            "sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config && systemctl reload sshd 2>/dev/null || true" \
            "sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config && systemctl reload sshd 2>/dev/null || true"
    else
        result_pass "SSH PasswordAuthentication" "$pwd_auth" "CIS 5.2.12"
    fi

    # Protocol (legacy check — OpenSSH 7.6+ removed Protocol 1)
    local protocol
    protocol=$(echo "$full_config" | grep -i "^Protocol" | tail -1 | awk '{print $2}' || true)
    if [[ -n "$protocol" ]] && [[ "$protocol" != "2" ]]; then
        result_fail "SSH Protocol" "Protocol $protocol allows insecure v1" \
            "Set Protocol 2 in sshd_config" "CIS 5.2.4"
    else
        result_pass "SSH Protocol" "v2 only" "CIS 5.2.4"
    fi

    # MaxAuthTries
    local max_auth
    max_auth=$(echo "$full_config" | grep -i "^MaxAuthTries" | tail -1 | awk '{print $2}' || true)
    if [[ -n "$max_auth" ]] && [[ "$max_auth" -le 4 ]]; then
        result_pass "SSH MaxAuthTries" "${max_auth}" "CIS 5.2.7"
    elif [[ -z "$max_auth" ]] || [[ "$max_auth" -gt 4 ]]; then
        result_warn "SSH MaxAuthTries" "${max_auth:-6 (default)}" \
            "Set MaxAuthTries 4 in sshd_config" "CIS 5.2.7"
    fi

    # LoginGraceTime
    local grace_time
    grace_time=$(echo "$full_config" | grep -i "^LoginGraceTime" | tail -1 | awk '{print $2}' || true)
    if [[ -n "$grace_time" ]] && [[ "$grace_time" -le 60 ]]; then
        result_pass "SSH LoginGraceTime" "${grace_time}s" "CIS 5.2.16"
    elif [[ -z "$grace_time" ]]; then
        result_warn "SSH LoginGraceTime" "120s (default)" \
            "Set LoginGraceTime 60 in sshd_config" "CIS 5.2.16"
    fi

    # ClientAliveInterval
    local alive_interval
    alive_interval=$(echo "$full_config" | grep -i "^ClientAliveInterval" | tail -1 | awk '{print $2}' || true)
    if [[ -n "$alive_interval" ]] && [[ "$alive_interval" -gt 0 ]] && [[ "$alive_interval" -le 300 ]]; then
        result_pass "SSH ClientAliveInterval" "${alive_interval}s" "CIS 5.2.16"
    else
        result_warn "SSH ClientAliveInterval" "${alive_interval:-0 (default)}" \
            "Set ClientAliveInterval 300 in sshd_config" "CIS 5.2.16"
    fi
}

# ---------------------------------------------------------------------------
# 8. Firewall Status
# ---------------------------------------------------------------------------
check_firewall() {
    section "Firewall"

    local has_firewall=0

    # nftables
    if command -v nft &>/dev/null; then
        local nft_rules
        nft_rules=$(nft list ruleset 2>/dev/null | grep -c "rule" || true)
        if [[ "$nft_rules" -gt 0 ]]; then
            result_pass "nftables rules present" "${nft_rules} rule(s)" "CIS 3.5"
            has_firewall=1
        else
            result_warn "nftables installed but no rules" "" \
                "Configure nftables firewall rules" "CIS 3.5"
        fi
    fi

    # iptables
    if command -v iptables &>/dev/null; then
        local ipt_rules
        ipt_rules=$(iptables -L -n 2>/dev/null | grep -cE "^(ACCEPT|DROP|REJECT|LOG)" || true)
        if [[ "$ipt_rules" -gt 0 ]]; then
            result_pass "iptables rules present" "${ipt_rules} rule(s)" "CIS 3.5"
            has_firewall=1
        else
            if [[ "$has_firewall" -eq 0 ]]; then
                result_warn "iptables installed but no rules" "" \
                    "Configure iptables or nftables firewall rules" "CIS 3.5"
            fi
        fi
    fi

    if [[ "$has_firewall" -eq 0 ]]; then
        if ! command -v nft &>/dev/null && ! command -v iptables &>/dev/null; then
            result_fail "No firewall tools found" "Neither iptables nor nftables installed" \
                "Install and configure nftables for network filtering" "CIS 3.5"
        fi
    fi
}

# ---------------------------------------------------------------------------
# 9. Kernel Module Loading Restrictions
# ---------------------------------------------------------------------------
check_module_loading() {
    section "Kernel Module Loading"

    # modules_disabled sysctl
    local mod_disabled
    mod_disabled=$(cat /proc/sys/kernel/modules_disabled 2>/dev/null || echo "unknown")
    if [[ "$mod_disabled" == "1" ]]; then
        result_pass "Kernel module loading disabled" "modules_disabled=1" "CIS 1.1.24"
    else
        result_warn "Kernel module loading allowed" "modules_disabled=${mod_disabled}" \
            "Set kernel.modules_disabled=1 after boot (one-way toggle)" "CIS 1.1.24"
        register_fix \
            "sysctl -w kernel.modules_disabled=1" \
            "# Cannot undo: modules_disabled is a one-way toggle. Reboot to reset."
    fi

    # Module signing enforcement
    local kconfig=""
    for cfg in /boot/config-"$(uname -r)" /proc/config.gz; do
        [[ -f "$cfg" ]] && kconfig="$cfg" && break
    done

    if [[ -n "$kconfig" ]]; then
        local reader="cat"
        [[ "$kconfig" == *.gz ]] && reader="zcat"

        if $reader "$kconfig" 2>/dev/null | grep -q "CONFIG_MODULE_SIG_FORCE=y"; then
            result_pass "Module signature enforcement enabled"
        else
            result_warn "Module signature enforcement not enabled" "" \
                "Rebuild kernel with CONFIG_MODULE_SIG_FORCE=y"
        fi
    fi

    # Blacklisted modules (common attack vectors)
    local modprobe_dir="/etc/modprobe.d"
    if [[ -d "$modprobe_dir" ]]; then
        local blacklisted
        blacklisted=$(grep -rh "^blacklist\|^install.*\/bin\/false\|^install.*\/bin\/true" \
            "$modprobe_dir" 2>/dev/null | wc -l || true)
        result_pass "Module blacklist entries" "${blacklisted} rule(s) in modprobe.d"
    fi
}

# ---------------------------------------------------------------------------
# 10. Core Dump Configuration
# ---------------------------------------------------------------------------
check_core_dumps() {
    section "Core Dumps"

    # /proc/sys/kernel/core_pattern
    local core_pattern
    core_pattern=$(cat /proc/sys/kernel/core_pattern 2>/dev/null || echo "unknown")
    if [[ "$core_pattern" == "" ]] || [[ "$core_pattern" == "|"* && "$core_pattern" == *"systemd-coredump"* ]]; then
        result_pass "Core dumps handled by systemd-coredump" "$core_pattern" "CIS 1.5.1"
    elif [[ "$core_pattern" == "core" ]] || [[ "$core_pattern" == "core."* ]]; then
        result_warn "Core dumps written to filesystem" "$core_pattern" \
            "Disable core dumps or pipe to systemd-coredump" "CIS 1.5.1"
    fi

    # fs.suid_dumpable
    local suid_dump
    suid_dump=$(cat /proc/sys/fs/suid_dumpable 2>/dev/null || echo "unknown")
    if [[ "$suid_dump" == "0" ]]; then
        result_pass "SUID core dumps disabled" "suid_dumpable=0" "CIS 1.5.1"
    elif [[ "$suid_dump" == "2" ]]; then
        result_warn "SUID core dumps in restricted mode" "suid_dumpable=2" \
            "Set fs.suid_dumpable=0 for maximum security" "CIS 1.5.1"
        register_fix \
            "sysctl -w fs.suid_dumpable=0 && echo 'fs.suid_dumpable = 0' >> /etc/sysctl.d/99-edge-hardener.conf" \
            "sysctl -w fs.suid_dumpable=2 && sed -i '/fs.suid_dumpable/d' /etc/sysctl.d/99-edge-hardener.conf"
    else
        result_fail "SUID core dumps enabled" "suid_dumpable=${suid_dump}" \
            "Set fs.suid_dumpable=0 in /etc/sysctl.d/" "CIS 1.5.1"
        register_fix \
            "sysctl -w fs.suid_dumpable=0 && echo 'fs.suid_dumpable = 0' >> /etc/sysctl.d/99-edge-hardener.conf" \
            "sysctl -w fs.suid_dumpable=${suid_dump} && sed -i '/fs.suid_dumpable/d' /etc/sysctl.d/99-edge-hardener.conf"
    fi

    # ulimit
    local ulimit_core
    ulimit_core=$(ulimit -c 2>/dev/null || echo "unknown")
    if [[ "$ulimit_core" == "0" ]]; then
        result_pass "Core dump ulimit" "ulimit -c = 0" "CIS 1.5.1"
    else
        result_warn "Core dump ulimit non-zero" "ulimit -c = ${ulimit_core}" \
            "Add '* hard core 0' to /etc/security/limits.conf" "CIS 1.5.1"
        register_fix \
            "echo '* hard core 0' >> /etc/security/limits.conf" \
            "sed -i '/\\* hard core 0/d' /etc/security/limits.conf"
    fi
}

# ---------------------------------------------------------------------------
# 11. Container Security
# ---------------------------------------------------------------------------
check_container_security() {
    section "Container Security"

    if [[ -f "${SCRIPT_DIR}/checks/container_audit.sh" ]]; then
        source "${SCRIPT_DIR}/checks/container_audit.sh"
        run_container_audit
    else
        result_warn "Container audit module not found" "checks/container_audit.sh missing"
    fi
}

# ---------------------------------------------------------------------------
# 12. Cryptographic Health
# ---------------------------------------------------------------------------
check_crypto_health() {
    section "Cryptographic Health"

    if [[ -f "${SCRIPT_DIR}/checks/crypto_audit.sh" ]]; then
        source "${SCRIPT_DIR}/checks/crypto_audit.sh"
        run_crypto_audit
    else
        result_warn "Crypto audit module not found" "checks/crypto_audit.sh missing"
    fi
}

# ---------------------------------------------------------------------------
# 13. Supply Chain / Binary Provenance
# ---------------------------------------------------------------------------
check_supply_chain() {
    section "Supply Chain / Binary Provenance"

    if [[ -f "${SCRIPT_DIR}/checks/supply_chain_audit.sh" ]]; then
        source "${SCRIPT_DIR}/checks/supply_chain_audit.sh"
        run_supply_chain_audit
    else
        result_warn "Supply chain audit module not found" "checks/supply_chain_audit.sh missing"
    fi
}

# ---------------------------------------------------------------------------
# 14. Bootloader Security
# ---------------------------------------------------------------------------
check_bootloader() {
    section "Bootloader Security"

    if [[ -f "${SCRIPT_DIR}/checks/bootloader_audit.sh" ]]; then
        source "${SCRIPT_DIR}/checks/bootloader_audit.sh"
        run_bootloader_audit
    else
        result_warn "Bootloader audit module not found" "checks/bootloader_audit.sh missing"
    fi
}

# ---------------------------------------------------------------------------
# 15. systemd Service Hardening
# ---------------------------------------------------------------------------
check_systemd_audit() {
    section "systemd Service Hardening"

    if [[ -f "${SCRIPT_DIR}/checks/systemd_audit.sh" ]]; then
        source "${SCRIPT_DIR}/checks/systemd_audit.sh"
        run_systemd_audit
    else
        result_warn "systemd audit module not found" "checks/systemd_audit.sh missing"
    fi
}

# ---------------------------------------------------------------------------
# 16. USB Device Policy
# ---------------------------------------------------------------------------
check_usb_audit() {
    section "USB Device Policy"

    if [[ -f "${SCRIPT_DIR}/checks/usb_audit.sh" ]]; then
        source "${SCRIPT_DIR}/checks/usb_audit.sh"
        run_usb_audit
    else
        result_warn "USB audit module not found" "checks/usb_audit.sh missing"
    fi
}

# ---------------------------------------------------------------------------
# JSON output
# ---------------------------------------------------------------------------
emit_json() {
    local outfile="${1:-}"
    local json
    json=$(build_current_json)

    if [[ -n "$outfile" ]]; then
        echo "$json" > "$outfile"
        echo ""
        echo -e "${BLUE}JSON report written to: ${outfile}${NC}"
    else
        echo "$json"
    fi
}

# ---------------------------------------------------------------------------
# CSV output
# ---------------------------------------------------------------------------
emit_csv() {
    local outfile="${1:-}"
    local csv="status,check,detail,category,remediation,cis_id\n"

    for r in "${JSON_RESULTS[@]}"; do
        local status check detail category remediation cis_id
        [[ "$r" =~ \"status\":\"([^\"]+)\" ]] && status="${BASH_REMATCH[1]}" || status=""
        [[ "$r" =~ \"check\":\"([^\"]+)\" ]] && check="${BASH_REMATCH[1]}" || check=""
        [[ "$r" =~ \"detail\":\"([^\"]+)\" ]] && detail="${BASH_REMATCH[1]}" || detail=""
        [[ "$r" =~ \"category\":\"([^\"]+)\" ]] && category="${BASH_REMATCH[1]}" || category=""
        [[ "$r" =~ \"remediation\":\"([^\"]+)\" ]] && remediation="${BASH_REMATCH[1]}" || remediation=""
        [[ "$r" =~ \"cis_id\":\"([^\"]+)\" ]] && cis_id="${BASH_REMATCH[1]}" || cis_id=""
        csv+="\"${status}\",\"${check}\",\"${detail}\",\"${category}\",\"${remediation}\",\"${cis_id}\"\n"
    done

    if [[ -n "$outfile" ]]; then
        echo -e "$csv" > "$outfile"
        echo -e "${BLUE}CSV report written to: ${outfile}${NC}"
    else
        echo -e "$csv"
    fi
}

# ---------------------------------------------------------------------------
# SARIF output (Static Analysis Results Interchange Format)
# ---------------------------------------------------------------------------
emit_sarif() {
    local outfile="${1:-}"

    # shellcheck disable=SC2016  # $schema is a literal JSON key, not a shell expansion
    local sarif='{"version":"2.1.0","$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json","runs":[{"tool":{"driver":{"name":"edge-hardener","version":"'"${VERSION}"'","informationUri":"https://isecwire.com/tools/edge-hardener","rules":['

    # Build rules array and results array
    local rules=""
    local results=""
    local idx=0

    for r in "${JSON_RESULTS[@]}"; do
        local status check detail category remediation cis_id
        [[ "$r" =~ \"status\":\"([^\"]+)\" ]] && status="${BASH_REMATCH[1]}" || status=""
        [[ "$r" =~ \"check\":\"([^\"]+)\" ]] && check="${BASH_REMATCH[1]}" || check=""
        [[ "$r" =~ \"detail\":\"([^\"]+)\" ]] && detail="${BASH_REMATCH[1]}" || detail=""
        [[ "$r" =~ \"category\":\"([^\"]+)\" ]] && category="${BASH_REMATCH[1]}" || category=""
        [[ "$r" =~ \"remediation\":\"([^\"]+)\" ]] && remediation="${BASH_REMATCH[1]}" || remediation=""
        [[ "$r" =~ \"cis_id\":\"([^\"]+)\" ]] && cis_id="${BASH_REMATCH[1]}" || cis_id=""

        # Generate a stable rule ID from category + check
        local esc_check; esc_check=$(_json_escape "$check")
        local esc_detail; esc_detail=$(_json_escape "$detail")
        local esc_category; esc_category=$(_json_escape "$category")
        local esc_remediation; esc_remediation=$(_json_escape "$remediation")

        local rule_id
        rule_id="EH$(printf '%04d' "$idx")"

        # Map status to SARIF level
        local level="note"
        if [[ "$status" == "FAIL" ]]; then
            level="error"
        elif [[ "$status" == "WARN" ]]; then
            level="warning"
        fi

        # Add rule definition (one per result for simplicity)
        [[ -n "$rules" ]] && rules+=","
        rules+="{\"id\":\"${rule_id}\",\"name\":\"${esc_check}\""
        rules+=",\"shortDescription\":{\"text\":\"${esc_check}\"}"
        if [[ -n "$remediation" ]]; then
            rules+=",\"helpUri\":\"\",\"help\":{\"text\":\"${esc_remediation}\"}"
        fi
        rules+=",\"properties\":{\"category\":\"${esc_category}\""
        [[ -n "$cis_id" ]] && rules+=",\"cis_id\":\"$(_json_escape "$cis_id")\""
        rules+="}}"

        # Add result
        [[ -n "$results" ]] && results+=","
        results+="{\"ruleId\":\"${rule_id}\",\"level\":\"${level}\""
        results+=",\"message\":{\"text\":\"${esc_check}"
        [[ -n "$detail" ]] && results+=" — ${esc_detail}"
        results+="\"}"
        results+=",\"locations\":[{\"physicalLocation\":{\"artifactLocation\":{\"uri\":\"$(hostname)\"}}}]"
        results+="}"

        idx=$((idx + 1))
    done

    sarif+="${rules}]}},\"results\":[${results}]"
    sarif+=",\"invocations\":[{\"executionSuccessful\":true,\"startTimeUtc\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}]"
    sarif+="}]}"

    if [[ -n "$outfile" ]]; then
        echo "$sarif" > "$outfile"
        echo -e "${BLUE}SARIF report written to: ${outfile}${NC}"
    else
        echo "$sarif"
    fi
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
print_summary() {
    echo ""
    echo -e "  ${BOLD}${CYAN}${BOX_TL}${BOX_H}${BOX_H}${NC} ${BOLD}Summary${NC} ${CYAN}$(printf '%0.s\xe2\x94\x80' {1..49})${BOX_TR}${NC}"
    echo ""
    echo -e "    Total checks : ${BOLD}${TOTAL_COUNT}${NC}"
    echo -e "    ${GREEN}PASS${NC}  : ${PASS_COUNT}"
    echo -e "    ${RED}FAIL${NC}  : ${FAIL_COUNT}"
    echo -e "    ${YELLOW}WARN${NC}  : ${WARN_COUNT}"

    # Risk score (0-100)
    local risk_score=0
    if [[ "$TOTAL_COUNT" -gt 0 ]]; then
        risk_score=$(( (FAIL_COUNT * 10 + WARN_COUNT * 3) * 100 / (TOTAL_COUNT * 10) ))
        [[ "$risk_score" -gt 100 ]] && risk_score=100
    fi
    echo ""
    local score_color="$GREEN"
    if [[ "$risk_score" -gt 50 ]]; then
        score_color="$RED"
    elif [[ "$risk_score" -gt 20 ]]; then
        score_color="$YELLOW"
    fi
    echo -e "    Risk Score : ${score_color}${BOLD}${risk_score}/100${NC} ${DIM}(lower is better)${NC}"

    # Pass percentage
    if [[ "$TOTAL_COUNT" -gt 0 ]]; then
        local pass_pct=$(( PASS_COUNT * 100 / TOTAL_COUNT ))
        echo -e "    Pass Rate  : ${BOLD}${pass_pct}%${NC}"
    fi

    # Policy compliance
    if [[ -n "$POLICY_NAME" ]]; then
        echo ""
        echo -e "    ${MAGENTA}${BOLD}Policy: ${POLICY_NAME}${NC}"
        local policy_pass=1
        if [[ "$FAIL_COUNT" -gt "$POLICY_MAX_FAIL" ]]; then
            echo -e "    ${RED}FAIL${NC}: ${FAIL_COUNT} failures exceed maximum ${POLICY_MAX_FAIL}"
            policy_pass=0
        fi
        if [[ "$WARN_COUNT" -gt "$POLICY_MAX_WARN" ]]; then
            echo -e "    ${YELLOW}WARN${NC}: ${WARN_COUNT} warnings exceed maximum ${POLICY_MAX_WARN}"
            policy_pass=0
        fi
        if [[ "$TOTAL_COUNT" -gt 0 ]]; then
            local pass_pct=$(( PASS_COUNT * 100 / TOTAL_COUNT ))
            if [[ "$pass_pct" -lt "$POLICY_MIN_PASS_PCT" ]]; then
                echo -e "    ${RED}FAIL${NC}: ${pass_pct}% pass rate below minimum ${POLICY_MIN_PASS_PCT}%"
                policy_pass=0
            fi
        fi
        if [[ "$policy_pass" -eq 1 ]]; then
            echo -e "    ${GREEN}${BOLD}Policy COMPLIANT${NC}"
        else
            echo -e "    ${RED}${BOLD}Policy NON-COMPLIANT${NC}"
        fi
    fi

    echo ""
    if [[ "$FAIL_COUNT" -gt 0 ]]; then
        echo -e "    ${RED}${BOLD}Action required — ${FAIL_COUNT} failing check(s).${NC}"
    elif [[ "$WARN_COUNT" -gt 0 ]]; then
        echo -e "    ${YELLOW}${BOLD}Review recommended — ${WARN_COUNT} warning(s).${NC}"
    else
        echo -e "    ${GREEN}${BOLD}All checks passed.${NC}"
    fi
    echo ""
}

# ---------------------------------------------------------------------------
# Count total checks for progress display
# ---------------------------------------------------------------------------
estimate_total_checks() {
    # Rough estimate based on enabled categories
    local count=0
    is_check_enabled "secure_boot" && count=$((count + 3))
    is_check_enabled "kernel_hardening" && count=$((count + 15))
    is_check_enabled "dm_verity" && count=$((count + 2))
    is_check_enabled "debug_interfaces" && count=$((count + 5))
    is_check_enabled "network_exposure" && count=$((count + 12))
    is_check_enabled "filesystem_permissions" && count=$((count + 10))
    is_check_enabled "ssh_hardening" && count=$((count + 7))
    is_check_enabled "firewall" && count=$((count + 3))
    is_check_enabled "module_loading" && count=$((count + 3))
    is_check_enabled "core_dumps" && count=$((count + 3))
    is_check_enabled "container_audit" && count=$((count + 10))
    is_check_enabled "crypto_audit" && count=$((count + 10))
    is_check_enabled "supply_chain_audit" && count=$((count + 8))
    is_check_enabled "bootloader_audit" && count=$((count + 8))
    is_check_enabled "systemd_audit" && count=$((count + 9))
    is_check_enabled "usb_audit" && count=$((count + 6))
    TOTAL_CHECKS=$count
}

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    cat << 'USAGE_EOF'
Usage: edge_hardener.sh [OPTIONS]

Embedded Linux security hardening auditor.

Options:
  -j, --json FILE       Write JSON results to FILE
  -q, --quiet           JSON output only (no terminal colors)
  -h, --help            Show this help
  -v, --version         Show version

  --policy FILE         Load a YAML policy profile for enforcement
  --checks LIST         Run only specified check categories (comma-separated)
  --exclude LIST        Skip specified check categories (comma-separated)

  --fix                 Apply safe automatic remediations
  --fix-script FILE     Generate fix script instead of applying directly

  --baseline FILE       Compare against a previous JSON export
  --format FORMAT       Output format: text (default), json, html, csv, sarif

Check categories:
  secure_boot, kernel_hardening, dm_verity, debug_interfaces,
  network_exposure, filesystem_permissions, ssh_hardening, firewall,
  module_loading, core_dumps, container_audit, crypto_audit,
  supply_chain_audit, bootloader_audit, systemd_audit, usb_audit

Exit codes:
  0   All checks passed
  1   Warnings detected (no failures)
  2   One or more checks failed
  3   Policy non-compliance (when --policy is used)

Examples:
  # Full audit with HTML report
  sudo ./edge_hardener.sh -j results.json
  python3 generate_report.py results.json -o report.html

  # Audit with industrial gateway policy
  sudo ./edge_hardener.sh --policy policies/industrial-gateway.yaml

  # Run only network and SSH checks
  sudo ./edge_hardener.sh --checks network_exposure,ssh_hardening

  # Generate fix script without applying
  sudo ./edge_hardener.sh --fix-script /tmp/fixes.sh

  # Compare against baseline
  sudo ./edge_hardener.sh -j current.json --baseline previous.json

  # CI/CD pipeline mode
  sudo ./edge_hardener.sh -q --policy policies/medical-device.yaml

Run as root for full coverage.
USAGE_EOF
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    local json_file=""
    local quiet=0

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -j|--json)       json_file="$2"; shift 2 ;;
            -q|--quiet)      quiet=1; shift ;;
            -h|--help)       usage; exit 0 ;;
            -v|--version)    echo "edge-hardener v${VERSION}"; exit 0 ;;
            --policy)        POLICY_FILE="$2"; shift 2 ;;
            --checks)        INCLUDE_CHECKS="$2"; shift 2 ;;
            --exclude)       EXCLUDE_CHECKS="$2"; shift 2 ;;
            --fix)           FIX_MODE=1; shift ;;
            --fix-script)    FIX_MODE=1; FIX_SCRIPT_FILE="$2"; shift 2 ;;
            --baseline)      BASELINE_FILE="$2"; shift 2 ;;
            --format)        OUTPUT_FORMAT="$2"; shift 2 ;;
            *) echo "Unknown option: $1"; usage; exit 1 ;;
        esac
    done

    # Load policy if specified
    if [[ -n "$POLICY_FILE" ]]; then
        load_policy "$POLICY_FILE"
    fi

    if [[ "$EUID" -ne 0 ]]; then
        echo -e "${YELLOW}Warning: Running without root privileges. Some checks may be incomplete.${NC}" >&2
        echo "" >&2
    fi

    if [[ "$quiet" -eq 0 ]]; then
        banner
        estimate_total_checks
    fi

    if [[ "$quiet" -eq 1 ]]; then
        # In quiet mode suppress terminal output from checks, keep JSON accumulation
        exec 3>&1 1>/dev/null
    fi

    # Run all enabled check categories
    is_check_enabled "secure_boot"           && check_secure_boot
    is_check_enabled "kernel_hardening"      && check_kernel_hardening
    is_check_enabled "dm_verity"             && check_dm_verity
    is_check_enabled "debug_interfaces"      && check_debug_interfaces
    is_check_enabled "network_exposure"      && check_network_exposure
    is_check_enabled "filesystem_permissions" && check_filesystem_permissions
    is_check_enabled "ssh_hardening"         && check_ssh_hardening
    is_check_enabled "firewall"              && check_firewall
    is_check_enabled "module_loading"        && check_module_loading
    is_check_enabled "core_dumps"            && check_core_dumps
    is_check_enabled "container_audit"       && check_container_security
    is_check_enabled "crypto_audit"          && check_crypto_health
    is_check_enabled "supply_chain_audit"    && check_supply_chain
    is_check_enabled "bootloader_audit"      && check_bootloader
    is_check_enabled "systemd_audit"        && check_systemd_audit
    is_check_enabled "usb_audit"            && check_usb_audit

    # Apply policy enforcement (elevate WARN to FAIL per policy)
    if [[ -n "$POLICY_FILE" ]] && [[ "${#JSON_RESULTS[@]}" -gt 0 ]]; then
        apply_policy_enforcement
    fi

    if [[ "$quiet" -eq 1 ]]; then
        exec 1>&3 3>&-
    else
        print_summary

        # Apply fixes if requested
        if [[ "$FIX_MODE" -eq 1 ]]; then
            apply_fixes
        fi

        # Baseline comparison
        if [[ -n "$BASELINE_FILE" ]]; then
            compare_baseline "$BASELINE_FILE"
        fi
    fi

    # Output based on format
    case "$OUTPUT_FORMAT" in
        json)
            emit_json "${json_file:-}"
            ;;
        html)
            # Write JSON first, then generate HTML
            local tmp_json
            tmp_json=$(mktemp /tmp/edge-hardener-XXXXXX.json)
            emit_json "$tmp_json"
            if [[ -f "${SCRIPT_DIR}/generate_report.py" ]]; then
                local html_file="${json_file%.json}.html"
                [[ -z "$json_file" ]] && html_file="report.html"
                python3 "${SCRIPT_DIR}/generate_report.py" "$tmp_json" -o "$html_file" 2>/dev/null || true
                echo -e "${BLUE}HTML report written to: ${html_file}${NC}"
            fi
            rm -f "$tmp_json"
            ;;
        csv)
            local csv_file="${json_file%.json}.csv"
            [[ -z "$json_file" ]] && csv_file="results.csv"
            emit_csv "$csv_file"
            ;;
        sarif)
            local sarif_file="${json_file%.json}.sarif"
            [[ -z "$json_file" ]] && sarif_file="results.sarif"
            emit_sarif "$sarif_file"
            ;;
        *)
            # Default text output — JSON file is optional extra
            if [[ -n "$json_file" ]]; then
                emit_json "$json_file"
            elif [[ "$quiet" -eq 1 ]]; then
                emit_json
            fi
            ;;
    esac

    # Exit code reflects findings
    if [[ -n "$POLICY_FILE" ]]; then
        local policy_pass=1
        if [[ "$FAIL_COUNT" -gt "$POLICY_MAX_FAIL" ]]; then
            policy_pass=0
        fi
        if [[ "$WARN_COUNT" -gt "$POLICY_MAX_WARN" ]]; then
            policy_pass=0
        fi
        if [[ "$TOTAL_COUNT" -gt 0 ]]; then
            local pass_pct=$(( PASS_COUNT * 100 / TOTAL_COUNT ))
            if [[ "$pass_pct" -lt "$POLICY_MIN_PASS_PCT" ]]; then
                policy_pass=0
            fi
        fi
        if [[ "$policy_pass" -eq 0 ]]; then
            exit 3
        fi
    fi

    if [[ "$FAIL_COUNT" -gt 0 ]]; then
        exit 2
    elif [[ "$WARN_COUNT" -gt 0 ]]; then
        exit 1
    fi
    exit 0
}

main "$@"
