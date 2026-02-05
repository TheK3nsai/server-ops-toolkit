#!/usr/bin/env bash
# fail2ban-status.sh - Check fail2ban status and banned IPs
#
# Purpose: Report fail2ban jail status, currently banned IPs,
#          ban statistics, and service health
#
# Usage: ./fail2ban-status.sh [--jail NAME] [--json] [--unban IP]
#        --jail NAME : Check specific jail only
#        --json      : Output in JSON format
#        --unban IP  : Unban specified IP from all jails
#
# Dependencies: fail2ban-client (fail2ban package)
#
# Exit codes: 0=healthy, 1=error, 2=service not running or issues

set -euo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../lib/common.sh"

# Configuration
SPECIFIC_JAIL=""
JSON_OUTPUT=false
UNBAN_IP=""

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --jail)
            SPECIFIC_JAIL="$2"
            shift 2
            ;;
        --json)
            JSON_OUTPUT=true
            shift
            ;;
        --unban)
            UNBAN_IP="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--jail NAME] [--json] [--unban IP]"
            echo "  --jail NAME : Check specific jail only"
            echo "  --json      : Output in JSON format"
            echo "  --unban IP  : Unban specified IP from all jails"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check if fail2ban is installed
if ! command -v fail2ban-client &>/dev/null; then
    if $JSON_OUTPUT; then
        echo '{"error": "fail2ban not installed", "installed": false}'
    else
        log_error "fail2ban is not installed"
        echo ""
        echo "Install with:"
        echo "  sudo dnf install -y fail2ban fail2ban-firewalld"
        echo ""
        echo "Then enable and start:"
        echo "  sudo systemctl enable --now fail2ban"
    fi
    exit 1
fi

# Check if service is running
if ! systemctl is-active --quiet fail2ban; then
    if $JSON_OUTPUT; then
        echo '{"error": "fail2ban not running", "service_active": false}'
    else
        log_error "fail2ban service is not running"
        echo ""
        echo "Start with:"
        echo "  sudo systemctl start fail2ban"
        echo ""
        echo "Check status:"
        echo "  sudo systemctl status fail2ban"
    fi
    exit 2
fi

# Handle unban request
if [[ -n "$UNBAN_IP" ]]; then
    log_info "Attempting to unban $UNBAN_IP from all jails..."
    jails=$(sudo fail2ban-client status | grep "Jail list:" | sed 's/.*Jail list:\s*//' | tr ',' '\n' | tr -d ' \t')

    unbanned=false
    for jail in $jails; do
        if sudo fail2ban-client set "$jail" unbanip "$UNBAN_IP" 2>/dev/null; then
            log_success "Unbanned $UNBAN_IP from jail: $jail"
            unbanned=true
        fi
    done

    if $unbanned; then
        log_success "Unban complete"
        exit 0
    else
        log_warn "$UNBAN_IP was not banned in any jail"
        exit 0
    fi
fi

# Function to get jail details
get_jail_info() {
    local jail="$1"
    local status
    status=$(sudo fail2ban-client status "$jail" 2>/dev/null) || return 1

    local filter_failures filter_banned current_banned banned_ips

    filter_failures=$(echo "$status" | grep "Currently failed:" | awk '{print $NF}')
    filter_banned=$(echo "$status" | grep "Total banned:" | awk '{print $NF}')
    current_banned=$(echo "$status" | grep "Currently banned:" | awk '{print $NF}')
    banned_ips=$(echo "$status" | grep "Banned IP list:" | sed 's/.*Banned IP list:\s*//' | tr -s '[:space:]' ' ')

    echo "${filter_failures:-0}|${filter_banned:-0}|${current_banned:-0}|${banned_ips:-}"
}

# Get list of jails
if [[ -n "$SPECIFIC_JAIL" ]]; then
    jails="$SPECIFIC_JAIL"
else
    jails=$(sudo fail2ban-client status | grep "Jail list:" | sed 's/.*Jail list:\s*//' | tr ',' '\n' | tr -d ' \t')
fi

# Collect data
declare -A jail_data
total_banned=0
total_currently_banned=0
all_banned_ips=""

for jail in $jails; do
    info=$(get_jail_info "$jail") || {
        jail_data["$jail"]="error"
        continue
    }
    jail_data["$jail"]="$info"

    IFS='|' read -r failures banned current ips <<< "$info"
    ((total_banned += banned)) || true
    ((total_currently_banned += current)) || true
    [[ -n "$ips" ]] && all_banned_ips="${all_banned_ips} ${ips}"
done

# Get fail2ban version and uptime
f2b_version=$(fail2ban-client --version 2>/dev/null | head -1 || echo "unknown")
f2b_pid=$(pgrep -x fail2ban-server 2>/dev/null || echo "")
f2b_uptime=""
if [[ -n "$f2b_pid" ]]; then
    f2b_uptime=$(ps -p "$f2b_pid" -o etime= 2>/dev/null | tr -d '[:space:]')
fi

# Output results
if $JSON_OUTPUT; then
    # Build JSON output
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"service\": {"
    echo "    \"active\": true,"
    echo "    \"version\": \"$f2b_version\","
    echo "    \"uptime\": \"${f2b_uptime:-unknown}\","
    echo "    \"pid\": ${f2b_pid:-null}"
    echo "  },"
    echo "  \"summary\": {"
    echo "    \"total_jails\": ${#jail_data[@]},"
    echo "    \"total_banned_all_time\": $total_banned,"
    echo "    \"currently_banned\": $total_currently_banned"
    echo "  },"
    echo "  \"jails\": {"

    first=true
    for jail in "${!jail_data[@]}"; do
        $first || echo ","
        first=false

        info="${jail_data[$jail]}"
        if [[ "$info" == "error" ]]; then
            printf '    "%s": {"error": true}' "$jail"
        else
            IFS='|' read -r failures banned current ips <<< "$info"
            printf '    "%s": {"currently_failed": %s, "total_banned": %s, "currently_banned": %s, "banned_ips": "%s"}' \
                "$jail" "$failures" "$banned" "$current" "$ips"
        fi
    done
    echo ""
    echo "  }"
    echo "}"
else
    # Human-readable output
    print_header "Fail2Ban Status Report"
    echo "Generated: $(date)"
    echo "Version:   $f2b_version"
    echo "Uptime:    ${f2b_uptime:-unknown}"
    echo "PID:       ${f2b_pid:-unknown}"

    print_header "Summary"
    echo "Active jails:           ${#jail_data[@]}"
    echo "Total bans (all time):  $total_banned"
    echo "Currently banned IPs:   $total_currently_banned"

    print_header "Jail Details"
    printf "%-20s %10s %12s %10s\n" "JAIL" "FAILED" "TOTAL BANS" "CURRENT"
    print_divider 55

    for jail in "${!jail_data[@]}"; do
        info="${jail_data[$jail]}"
        if [[ "$info" == "error" ]]; then
            printf "%-20s %10s\n" "$jail" "ERROR"
        else
            IFS='|' read -r failures banned current ips <<< "$info"
            printf "%-20s %10s %12s %10s\n" "$jail" "$failures" "$banned" "$current"
        fi
    done

    if [[ -n "${all_banned_ips// /}" ]]; then
        print_header "Currently Banned IPs"
        echo "$all_banned_ips" | tr ' ' '\n' | sort -u | grep -v '^$' | while read -r ip; do
            # Try to identify which jail(s)
            jails_with_ip=""
            for jail in "${!jail_data[@]}"; do
                [[ "${jail_data[$jail]}" == *"$ip"* ]] && jails_with_ip="${jails_with_ip} ${jail}"
            done
            printf "  %-18s in:%s\n" "$ip" "$jails_with_ip"
        done
    fi

    # Check for potential issues
    print_header "Health Check"
    issues=0

    # Check if sshd jail exists and is active
    if [[ -z "${jail_data[sshd]:-}" ]]; then
        log_warn "sshd jail not configured - SSH protection may be missing"
        ((issues++)) || true
    fi

    # Check for recurring jail
    if [[ -z "${jail_data[recidive]:-}" ]]; then
        log_info "Tip: Consider adding 'recidive' jail for repeat offenders"
    fi

    if [[ $issues -eq 0 ]]; then
        log_success "Fail2ban is healthy"
    fi

    print_divider

    echo ""
    echo "Quick commands:"
    echo "  Unban IP:    sudo fail2ban-client set <jail> unbanip <IP>"
    echo "  Ban IP:      sudo fail2ban-client set <jail> banip <IP>"
    echo "  Check IP:    sudo fail2ban-client status <jail> | grep <IP>"
    echo "  This script: $0 --unban <IP>"
fi

# Notify Uptime Kuma if configured
if [[ -n "${UPTIME_KUMA_F2B_PUSH:-}" ]]; then
    notify_uptime_kuma "$UPTIME_KUMA_F2B_PUSH" "up" "fail2ban active, ${total_currently_banned} IPs banned"
fi

exit 0
