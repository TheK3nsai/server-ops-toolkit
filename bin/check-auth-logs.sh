#!/usr/bin/env bash
# check-auth-logs.sh - Analyze authentication logs for suspicious activity
#
# Purpose: Parse /var/log/secure for failed logins, successful SSH connections,
#          sudo usage, and other security-relevant events
#
# Usage: ./check-auth-logs.sh [--hours N] [--quiet] [--json]
#        --hours N   : Look back N hours (default: 24)
#        --quiet     : Only output if issues found (for cron)
#        --json      : Output in JSON format
#
# Dependencies: grep, awk, sort, uniq (standard utils)
#
# Exit codes: 0=clean, 1=error, 2=suspicious activity found

set -euo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../lib/common.sh"

# Configuration
AUTH_LOG="/var/log/secure"
HOURS=24
QUIET=false
JSON_OUTPUT=false
FAILED_LOGIN_THRESHOLD=5     # Alert if IP has more than this many failures
SUDO_ALERT_COMMANDS=("rm -rf" "chmod 777" "passwd root" "visudo")

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --hours)
            HOURS="$2"
            shift 2
            ;;
        --quiet)
            QUIET=true
            shift
            ;;
        --json)
            JSON_OUTPUT=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--hours N] [--quiet] [--json]"
            echo "  --hours N  : Look back N hours (default: 24)"
            echo "  --quiet    : Only output if issues found"
            echo "  --json     : Output in JSON format"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check if we can read the log
if [[ ! -r "$AUTH_LOG" ]]; then
    log_error "Cannot read $AUTH_LOG - run with sudo"
    exit 1
fi

# Calculate time boundary
START_TIME=$(date -d "${HOURS} hours ago" '+%b %e %H:%M:%S')
START_EPOCH=$(date -d "${HOURS} hours ago" '+%s')

# Initialize counters
declare -A failed_by_ip=()
declare -A failed_by_user=()
declare -A success_by_ip=()
declare -a sudo_commands=()
declare -a root_logins=()
declare -a new_sessions=()
issues_found=0

# Process log file
while IFS= read -r line; do
    # Extract timestamp and check if within time range
    log_date=$(echo "$line" | awk '{print $1, $2, $3}')
    # Handle year rollover - assume current year
    log_epoch=$(date -d "${log_date} $(date +%Y)" '+%s' 2>/dev/null) || continue

    [[ $log_epoch -lt $START_EPOCH ]] && continue

    # Failed password attempts
    if echo "$line" | grep -q "Failed password"; then
        ip=$(echo "$line" | grep -oP 'from \K[0-9.]+' || echo "unknown")
        user=$(echo "$line" | grep -oP 'for (invalid user )?\K\w+' || echo "unknown")
        ((failed_by_ip["$ip"]++)) || true
        ((failed_by_user["$user"]++)) || true
    fi

    # Successful SSH logins
    if echo "$line" | grep -q "Accepted \(password\|publickey\)"; then
        ip=$(echo "$line" | grep -oP 'from \K[0-9.]+' || echo "unknown")
        user=$(echo "$line" | grep -oP 'for \K\w+' || echo "unknown")
        method=$(echo "$line" | grep -oP 'Accepted \K\w+' || echo "unknown")
        ((success_by_ip["$ip"]++)) || true
        new_sessions+=("${user}@${ip} (${method})")

        # Flag root logins
        if [[ "$user" == "root" ]]; then
            root_logins+=("$line")
        fi
    fi

    # Sudo commands
    if echo "$line" | grep -q "sudo:.*COMMAND="; then
        cmd=$(echo "$line" | grep -oP 'COMMAND=\K.*' || echo "")
        user=$(echo "$line" | grep -oP 'sudo:\s+\K\w+' || echo "unknown")
        sudo_commands+=("${user}: ${cmd}")
    fi

    # Failed sudo attempts
    if echo "$line" | grep -qE "(authentication failure|NOT in sudoers)"; then
        issues_found=1
    fi

done < "$AUTH_LOG"

# Identify suspicious IPs (exceeding threshold)
declare -a suspicious_ips=()
for ip in "${!failed_by_ip[@]}"; do
    if [[ ${failed_by_ip[$ip]} -ge $FAILED_LOGIN_THRESHOLD ]]; then
        suspicious_ips+=("$ip:${failed_by_ip[$ip]}")
        issues_found=1
    fi
done

# Check for suspicious sudo commands
declare -a suspicious_sudo=()
for cmd in "${sudo_commands[@]:-}"; do
    for pattern in "${SUDO_ALERT_COMMANDS[@]}"; do
        if [[ "$cmd" == *"$pattern"* ]]; then
            suspicious_sudo+=("$cmd")
            issues_found=1
        fi
    done
done

# Output results
if $JSON_OUTPUT; then
    # JSON output
    cat <<EOF
{
  "period_hours": $HOURS,
  "timestamp": "$(date -Iseconds)",
  "summary": {
    "total_failed_attempts": $(IFS=+; echo "$((${failed_by_ip[*]:-0}))"),
    "unique_source_ips": ${#failed_by_ip[@]},
    "successful_logins": ${#new_sessions[@]},
    "sudo_commands": ${#sudo_commands[@]},
    "root_logins": ${#root_logins[@]}
  },
  "suspicious_ips": [$(printf '"%s",' "${suspicious_ips[@]:-}" | sed 's/,$//')],
  "failed_users": {$(for u in "${!failed_by_user[@]}"; do printf '"%s":%d,' "$u" "${failed_by_user[$u]}"; done | sed 's/,$//')},
  "issues_found": $( $issues_found && echo "true" || echo "false" )
}
EOF
else
    # Human-readable output
    if ! $QUIET || [[ $issues_found -eq 1 ]]; then
        print_header "Authentication Log Analysis (Last ${HOURS}h)"
        echo "Report generated: $(date)"
        echo "Log file: $AUTH_LOG"

        print_header "Summary"
        total_failed=0
        for count in "${failed_by_ip[@]:-}"; do
            ((total_failed += count)) || true
        done
        echo "Failed login attempts:  $total_failed"
        echo "Unique source IPs:      ${#failed_by_ip[@]}"
        echo "Successful SSH logins:  ${#new_sessions[@]}"
        echo "Sudo commands executed: ${#sudo_commands[@]}"
        echo "Root logins:            ${#root_logins[@]}"

        if [[ ${#suspicious_ips[@]} -gt 0 ]]; then
            print_header "⚠ Suspicious IPs (>${FAILED_LOGIN_THRESHOLD} failures)"
            for entry in "${suspicious_ips[@]}"; do
                ip="${entry%:*}"
                count="${entry#*:}"
                printf "  %-20s %d failed attempts\n" "$ip" "$count"
            done
        fi

        if [[ ${#failed_by_user[@]} -gt 0 ]]; then
            print_header "Failed Login Attempts by User"
            for user in "${!failed_by_user[@]}"; do
                printf "  %-20s %d attempts\n" "$user" "${failed_by_user[$user]}"
            done | sort -t$'\t' -k2 -rn | head -10
        fi

        if [[ ${#new_sessions[@]} -gt 0 ]]; then
            print_header "Successful SSH Sessions"
            printf '%s\n' "${new_sessions[@]}" | sort -u | while read -r session; do
                echo "  $session"
            done
        fi

        if [[ ${#root_logins[@]} -gt 0 ]]; then
            print_header "⚠ Root Login Events"
            printf '%s\n' "${root_logins[@]}"
        fi

        if [[ ${#suspicious_sudo[@]} -gt 0 ]]; then
            print_header "⚠ Suspicious Sudo Commands"
            printf '%s\n' "${suspicious_sudo[@]}"
        fi

        print_divider
        if [[ $issues_found -eq 1 ]]; then
            log_warn "Suspicious activity detected - review above"
        else
            log_success "No suspicious activity detected"
        fi
    fi
fi

# Notify if configured and issues found
if [[ $issues_found -eq 1 ]] && [[ -n "${UPTIME_KUMA_AUTH_PUSH:-}" ]]; then
    notify_uptime_kuma "$UPTIME_KUMA_AUTH_PUSH" "down" "Suspicious auth activity detected"
elif [[ -n "${UPTIME_KUMA_AUTH_PUSH:-}" ]]; then
    notify_uptime_kuma "$UPTIME_KUMA_AUTH_PUSH" "up" "Auth logs clean"
fi

exit $issues_found
