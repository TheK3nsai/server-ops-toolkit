#!/usr/bin/env bash
# login-history.sh - Detailed login history report
#
# Purpose: Generate detailed login history including successful logins,
#          failed attempts, session durations, and source IP analysis
#
# Usage: ./login-history.sh [--days N] [--user NAME] [--json] [--failed-only]
#        --days N       : Report period in days (default: 7)
#        --user NAME    : Filter to specific user
#        --json         : Output in JSON format
#        --failed-only  : Only show failed login attempts
#        --ip IP        : Filter to specific source IP
#
# Dependencies: last, lastlog, /var/log/secure access
#
# Exit codes: 0=success, 1=error

set -euo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../lib/common.sh"

# Configuration
REPORT_DAYS=7
FILTER_USER=""
FILTER_IP=""
JSON_OUTPUT=false
FAILED_ONLY=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --days)
            REPORT_DAYS="$2"
            shift 2
            ;;
        --user)
            FILTER_USER="$2"
            shift 2
            ;;
        --ip)
            FILTER_IP="$2"
            shift 2
            ;;
        --json)
            JSON_OUTPUT=true
            shift
            ;;
        --failed-only)
            FAILED_ONLY=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--days N] [--user NAME] [--ip IP] [--json] [--failed-only]"
            echo ""
            echo "Options:"
            echo "  --days N       : Report period in days (default: 7)"
            echo "  --user NAME    : Filter to specific user"
            echo "  --ip IP        : Filter to specific source IP"
            echo "  --json         : Output in JSON format"
            echo "  --failed-only  : Only show failed login attempts"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Calculate date range
START_DATE=$(date -d "${REPORT_DAYS} days ago" '+%Y-%m-%d')
END_DATE=$(date '+%Y-%m-%d')
START_EPOCH=$(date -d "${REPORT_DAYS} days ago" '+%s')

# ============================================================================
# Collect Login Data
# ============================================================================

# Successful logins from last command
declare -a successful_logins=()
declare -A user_sessions=()
declare -A ip_logins=()
declare -A user_ips=()
total_sessions=0
total_duration_mins=0

while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^reboot ]] && continue
    [[ "$line" =~ ^wtmp ]] && continue
    [[ "$line" =~ "still logged in" ]] || [[ "$line" =~ "gone" ]] || true

    user=$(echo "$line" | awk '{print $1}')
    tty=$(echo "$line" | awk '{print $2}')
    ip=$(echo "$line" | awk '{print $3}')
    # Handle entries without IP
    if [[ "$ip" =~ ^[A-Z][a-z]{2}$ ]]; then
        ip="local"
    fi

    # Extract date/time - format varies
    datetime=$(echo "$line" | awk '{print $4, $5, $6, $7}')

    # Extract duration if available
    duration=$(echo "$line" | grep -oP '\(\K[0-9:+]+(?=\))' || echo "")

    # Apply filters
    [[ -n "$FILTER_USER" ]] && [[ "$user" != "$FILTER_USER" ]] && continue
    [[ -n "$FILTER_IP" ]] && [[ "$ip" != "$FILTER_IP" ]] && continue

    successful_logins+=("$user|$tty|$ip|$datetime|$duration")

    # Track statistics
    ((user_sessions[$user]++)) || true
    ((ip_logins[$ip]++)) || true
    user_ips[$user]="${user_ips[$user]:-},$ip"
    ((total_sessions++)) || true

    # Calculate duration in minutes if available
    if [[ "$duration" =~ ^([0-9]+):([0-9]+)$ ]]; then
        hours="${BASH_REMATCH[1]}"
        mins="${BASH_REMATCH[2]}"
        ((total_duration_mins += hours * 60 + mins)) || true
    fi
done < <(last -${REPORT_DAYS}d 2>/dev/null || last | head -200)

# Failed logins from secure log
declare -a failed_logins=()
declare -A failed_by_ip=()
declare -A failed_by_user=()
total_failed=0

if [[ -r /var/log/secure ]]; then
    while IFS= read -r line; do
        # Extract timestamp
        log_month=$(echo "$line" | awk '{print $1}')
        log_day=$(echo "$line" | awk '{print $2}')
        log_time=$(echo "$line" | awk '{print $3}')

        # Check if within date range (simplified)
        log_date="$log_month $log_day"

        ip=$(echo "$line" | grep -oP 'from \K[0-9.]+' || echo "unknown")
        user=$(echo "$line" | grep -oP 'for (invalid user )?\K\w+' || echo "unknown")
        invalid=""
        echo "$line" | grep -q "invalid user" && invalid="(invalid)"

        # Apply filters
        [[ -n "$FILTER_USER" ]] && [[ "$user" != "$FILTER_USER" ]] && continue
        [[ -n "$FILTER_IP" ]] && [[ "$ip" != "$FILTER_IP" ]] && continue

        failed_logins+=("$user|$ip|$log_date $log_time|$invalid")
        ((failed_by_ip[$ip]++)) || true
        ((failed_by_user[$user]++)) || true
        ((total_failed++)) || true
    done < <(grep "Failed password" /var/log/secure 2>/dev/null | tail -500)
fi

# Currently logged in users
declare -a current_sessions=()
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    user=$(echo "$line" | awk '{print $1}')
    tty=$(echo "$line" | awk '{print $2}')
    ip=$(echo "$line" | awk '{print $3}')
    login_time=$(echo "$line" | awk '{print $4, $5}')

    [[ -n "$FILTER_USER" ]] && [[ "$user" != "$FILTER_USER" ]] && continue

    current_sessions+=("$user|$tty|$ip|$login_time")
done < <(who 2>/dev/null)

# Last login times from lastlog
declare -A last_login_times=()
while IFS= read -r line; do
    [[ "$line" =~ ^Username ]] && continue
    [[ "$line" =~ "Never logged in" ]] && continue

    user=$(echo "$line" | awk '{print $1}')
    # Skip system users
    [[ "$user" =~ ^(daemon|bin|sys|sync|games|man|lp|mail|news) ]] && continue

    port=$(echo "$line" | awk '{print $2}')
    from=$(echo "$line" | awk '{print $3}')
    datetime=$(echo "$line" | awk '{$1=$2=$3=""; print $0}' | xargs)

    [[ -n "$FILTER_USER" ]] && [[ "$user" != "$FILTER_USER" ]] && continue

    last_login_times[$user]="$datetime from $from"
done < <(lastlog 2>/dev/null | head -50)

# ============================================================================
# Output Report
# ============================================================================

if $JSON_OUTPUT; then
    cat <<EOF
{
  "report_type": "Login History Report",
  "generated": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "period": {
    "days": $REPORT_DAYS,
    "start": "$START_DATE",
    "end": "$END_DATE"
  },
  "filters": {
    "user": "${FILTER_USER:-null}",
    "ip": "${FILTER_IP:-null}",
    "failed_only": $FAILED_ONLY
  },
  "summary": {
    "total_successful_sessions": $total_sessions,
    "total_failed_attempts": $total_failed,
    "unique_users": ${#user_sessions[@]},
    "unique_source_ips": ${#ip_logins[@]},
    "currently_logged_in": ${#current_sessions[@]},
    "total_session_duration_mins": $total_duration_mins
  },
EOF

    if ! $FAILED_ONLY; then
        echo '  "successful_logins": ['
        first=true
        for entry in "${successful_logins[@]:-}"; do
            IFS='|' read -r user tty ip datetime duration <<< "$entry"
            $first || echo ","
            first=false
            printf '    {"user": "%s", "tty": "%s", "ip": "%s", "datetime": "%s", "duration": "%s"}' \
                "$user" "$tty" "$ip" "$datetime" "$duration"
        done
        echo ""
        echo "  ],"
    fi

    echo '  "failed_logins": ['
    first=true
    for entry in "${failed_logins[@]:-}"; do
        IFS='|' read -r user ip datetime invalid <<< "$entry"
        $first || echo ","
        first=false
        printf '    {"user": "%s", "ip": "%s", "datetime": "%s", "invalid_user": %s}' \
            "$user" "$ip" "$datetime" "$( [[ -n "$invalid" ]] && echo "true" || echo "false" )"
    done
    echo ""
    echo "  ],"

    echo '  "current_sessions": ['
    first=true
    for entry in "${current_sessions[@]:-}"; do
        IFS='|' read -r user tty ip login_time <<< "$entry"
        $first || echo ","
        first=false
        printf '    {"user": "%s", "tty": "%s", "ip": "%s", "since": "%s"}' \
            "$user" "$tty" "$ip" "$login_time"
    done
    echo ""
    echo "  ],"

    echo '  "logins_by_user": {'
    first=true
    for user in "${!user_sessions[@]}"; do
        $first || echo ","
        first=false
        unique_ips=$(echo "${user_ips[$user]}" | tr ',' '\n' | sort -u | grep -v '^$' | wc -l)
        printf '    "%s": {"sessions": %d, "unique_ips": %d}' "$user" "${user_sessions[$user]}" "$unique_ips"
    done
    echo ""
    echo "  },"

    echo '  "logins_by_ip": {'
    first=true
    for ip in "${!ip_logins[@]}"; do
        $first || echo ","
        first=false
        printf '    "%s": %d' "$ip" "${ip_logins[$ip]}"
    done
    echo ""
    echo "  },"

    echo '  "failed_by_ip": {'
    first=true
    for ip in "${!failed_by_ip[@]}"; do
        $first || echo ","
        first=false
        printf '    "%s": %d' "$ip" "${failed_by_ip[$ip]}"
    done
    echo ""
    echo "  }"

    echo "}"
else
    # Human-readable output
    print_header "LOGIN HISTORY REPORT"
    echo "Generated: $(date)"
    echo "Hostname:  $(hostname)"
    echo "Period:    $START_DATE to $END_DATE ($REPORT_DAYS days)"
    [[ -n "$FILTER_USER" ]] && echo "User:      $FILTER_USER"
    [[ -n "$FILTER_IP" ]] && echo "IP:        $FILTER_IP"

    print_header "SUMMARY"
    echo "Successful login sessions: $total_sessions"
    echo "Failed login attempts:     $total_failed"
    echo "Unique users:              ${#user_sessions[@]}"
    echo "Unique source IPs:         ${#ip_logins[@]}"
    echo "Currently logged in:       ${#current_sessions[@]}"
    if [[ $total_duration_mins -gt 0 ]]; then
        echo "Total session time:        $((total_duration_mins / 60))h $((total_duration_mins % 60))m"
    fi

    # Current sessions
    if [[ ${#current_sessions[@]} -gt 0 ]]; then
        print_header "CURRENTLY LOGGED IN"
        printf "%-12s %-8s %-18s %s\n" "USER" "TTY" "FROM" "SINCE"
        print_divider 55
        for entry in "${current_sessions[@]}"; do
            IFS='|' read -r user tty ip login_time <<< "$entry"
            printf "%-12s %-8s %-18s %s\n" "$user" "$tty" "$ip" "$login_time"
        done
    fi

    # Successful logins (unless failed-only)
    if ! $FAILED_ONLY && [[ ${#successful_logins[@]} -gt 0 ]]; then
        print_header "SUCCESSFUL LOGINS (Last $REPORT_DAYS days)"
        printf "%-12s %-8s %-18s %-20s %s\n" "USER" "TTY" "FROM" "DATE/TIME" "DURATION"
        print_divider 75
        for entry in "${successful_logins[@]}"; do
            IFS='|' read -r user tty ip datetime duration <<< "$entry"
            printf "%-12s %-8s %-18s %-20s %s\n" "$user" "$tty" "${ip:0:17}" "${datetime:0:19}" "$duration"
        done | head -50

        if [[ ${#successful_logins[@]} -gt 50 ]]; then
            echo "... and $((${#successful_logins[@]} - 50)) more sessions"
        fi
    fi

    # Failed logins
    if [[ ${#failed_logins[@]} -gt 0 ]]; then
        print_header "FAILED LOGIN ATTEMPTS"
        printf "%-15s %-18s %-25s %s\n" "USER" "FROM IP" "DATE/TIME" "NOTE"
        print_divider 70
        for entry in "${failed_logins[@]}"; do
            IFS='|' read -r user ip datetime invalid <<< "$entry"
            printf "%-15s %-18s %-25s %s\n" "$user" "$ip" "$datetime" "$invalid"
        done | head -50

        if [[ ${#failed_logins[@]} -gt 50 ]]; then
            echo "... and $((${#failed_logins[@]} - 50)) more attempts"
        fi
    fi

    # Login statistics by user
    if [[ ${#user_sessions[@]} -gt 0 ]]; then
        print_header "LOGINS BY USER"
        printf "%-15s %10s %12s\n" "USER" "SESSIONS" "UNIQUE IPs"
        print_divider 40
        for user in "${!user_sessions[@]}"; do
            unique_ips=$(echo "${user_ips[$user]}" | tr ',' '\n' | sort -u | grep -v '^$' | wc -l)
            printf "%-15s %10d %12d\n" "$user" "${user_sessions[$user]}" "$unique_ips"
        done | sort -k2 -rn
    fi

    # Top source IPs
    if [[ ${#ip_logins[@]} -gt 0 ]]; then
        print_header "TOP SOURCE IPs (Successful)"
        printf "%-20s %10s\n" "IP ADDRESS" "LOGINS"
        print_divider 35
        for ip in "${!ip_logins[@]}"; do
            echo "$ip ${ip_logins[$ip]}"
        done | sort -k2 -rn | head -10 | while read -r ip count; do
            printf "%-20s %10d\n" "$ip" "$count"
        done
    fi

    # Failed login sources
    if [[ ${#failed_by_ip[@]} -gt 0 ]]; then
        print_header "TOP FAILED LOGIN SOURCES"
        printf "%-20s %10s\n" "IP ADDRESS" "ATTEMPTS"
        print_divider 35
        for ip in "${!failed_by_ip[@]}"; do
            echo "$ip ${failed_by_ip[$ip]}"
        done | sort -k2 -rn | head -10 | while read -r ip count; do
            printf "%-20s %10d\n" "$ip" "$count"
        done
    fi

    # Last login times
    if [[ ${#last_login_times[@]} -gt 0 ]] && ! $FAILED_ONLY; then
        print_header "LAST LOGIN TIMES"
        for user in "${!last_login_times[@]}"; do
            printf "%-15s %s\n" "$user" "${last_login_times[$user]}"
        done
    fi

    print_divider
    log_success "Report complete"
fi

exit 0
