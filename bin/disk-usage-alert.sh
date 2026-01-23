#!/usr/bin/env bash
# disk-usage-alert.sh - Monitor disk usage and alert on thresholds
#
# Purpose: Check disk usage on all mounted filesystems, alert when
#          thresholds are exceeded, and identify large files/directories
#
# Usage: ./disk-usage-alert.sh [--json] [--check-inodes] [--top N]
#        --json         : Output in JSON format
#        --check-inodes : Also check inode usage
#        --top N        : Show top N largest directories (default: 10)
#
# Dependencies: df, du, find (standard utils)
#
# Exit codes: 0=ok, 1=error, 2=warning threshold, 3=critical threshold

set -euo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../lib/common.sh"

# Configuration
WARN_THRESHOLD="${DISK_WARN_THRESHOLD:-80}"
CRIT_THRESHOLD="${DISK_CRIT_THRESHOLD:-90}"
INODE_WARN_THRESHOLD="${INODE_WARN_THRESHOLD:-80}"
JSON_OUTPUT=false
CHECK_INODES=false
TOP_N=10

# Filesystems to skip (pseudo filesystems)
SKIP_FS="tmpfs|devtmpfs|squashfs|overlay|none"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --json)
            JSON_OUTPUT=true
            shift
            ;;
        --check-inodes)
            CHECK_INODES=true
            shift
            ;;
        --top)
            TOP_N="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--json] [--check-inodes] [--top N]"
            echo "  --json         : Output in JSON format"
            echo "  --check-inodes : Also check inode usage"
            echo "  --top N        : Show top N largest directories (default: 10)"
            echo ""
            echo "Thresholds (set via env or conf/.env):"
            echo "  DISK_WARN_THRESHOLD=${WARN_THRESHOLD}%"
            echo "  DISK_CRIT_THRESHOLD=${CRIT_THRESHOLD}%"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Track status
exit_code=0
declare -a warnings=()
declare -a criticals=()

# Collect filesystem data
declare -a fs_data=()

while IFS= read -r line; do
    # Skip header and pseudo filesystems
    [[ "$line" =~ ^Filesystem ]] && continue
    fs_type=$(echo "$line" | awk '{print $1}')
    [[ "$fs_type" =~ ^($SKIP_FS)$ ]] && continue

    # Parse df output
    filesystem=$(echo "$line" | awk '{print $1}')
    size=$(echo "$line" | awk '{print $2}')
    used=$(echo "$line" | awk '{print $3}')
    avail=$(echo "$line" | awk '{print $4}')
    use_percent=$(echo "$line" | awk '{print $5}' | tr -d '%')
    mount=$(echo "$line" | awk '{print $6}')

    # Skip if we couldn't parse percentage
    [[ ! "$use_percent" =~ ^[0-9]+$ ]] && continue

    # Determine status
    status="ok"
    if [[ $use_percent -ge $CRIT_THRESHOLD ]]; then
        status="critical"
        criticals+=("$mount: ${use_percent}%")
        [[ $exit_code -lt 3 ]] && exit_code=3
    elif [[ $use_percent -ge $WARN_THRESHOLD ]]; then
        status="warning"
        warnings+=("$mount: ${use_percent}%")
        [[ $exit_code -lt 2 ]] && exit_code=2
    fi

    fs_data+=("${mount}|${filesystem}|${size}|${used}|${avail}|${use_percent}|${status}")
done < <(df -h 2>/dev/null)

# Collect inode data if requested
declare -a inode_data=()
if $CHECK_INODES; then
    while IFS= read -r line; do
        [[ "$line" =~ ^Filesystem ]] && continue
        fs_type=$(echo "$line" | awk '{print $1}')
        [[ "$fs_type" =~ ^($SKIP_FS)$ ]] && continue

        filesystem=$(echo "$line" | awk '{print $1}')
        inodes=$(echo "$line" | awk '{print $2}')
        iused=$(echo "$line" | awk '{print $3}')
        ifree=$(echo "$line" | awk '{print $4}')
        iuse_percent=$(echo "$line" | awk '{print $5}' | tr -d '%')
        mount=$(echo "$line" | awk '{print $6}')

        [[ ! "$iuse_percent" =~ ^[0-9]+$ ]] && continue
        [[ "$inodes" == "-" ]] && continue

        status="ok"
        if [[ $iuse_percent -ge $INODE_WARN_THRESHOLD ]]; then
            status="warning"
            warnings+=("$mount inodes: ${iuse_percent}%")
            [[ $exit_code -lt 2 ]] && exit_code=2
        fi

        inode_data+=("${mount}|${inodes}|${iused}|${ifree}|${iuse_percent}|${status}")
    done < <(df -i 2>/dev/null)
fi

# Find largest directories on root filesystem
get_large_dirs() {
    local mount="$1"
    local count="$2"

    # Only scan actual filesystems, skip special mounts
    [[ "$mount" == "/" ]] || return

    # Find large directories with timeout, exclude special paths
    # Using timeout to prevent hanging on slow/large filesystems
    timeout 30 du -xh --max-depth=2 "$mount" \
        --exclude=/proc \
        --exclude=/sys \
        --exclude=/dev \
        --exclude=/run \
        --exclude=/var/lib/docker \
        --exclude=/snap \
        2>/dev/null | \
        grep -vE "^0" | \
        sort -rh | \
        head -n "$count" || echo "  Scan timed out or failed"
}

# Output results
if $JSON_OUTPUT; then
    cat <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "thresholds": {
    "warning": $WARN_THRESHOLD,
    "critical": $CRIT_THRESHOLD
  },
  "status": "$([ $exit_code -eq 0 ] && echo "ok" || ([ $exit_code -eq 2 ] && echo "warning" || echo "critical"))",
  "filesystems": [
$(first=true
for entry in "${fs_data[@]}"; do
    IFS='|' read -r mount fs size used avail percent status <<< "$entry"
    $first || echo ","
    first=false
    printf '    {"mount": "%s", "filesystem": "%s", "size": "%s", "used": "%s", "available": "%s", "percent": %s, "status": "%s"}' \
        "$mount" "$fs" "$size" "$used" "$avail" "$percent" "$status"
done)
  ],
  "warnings": [$(printf '"%s",' "${warnings[@]:-}" | sed 's/,$//')],
  "criticals": [$(printf '"%s",' "${criticals[@]:-}" | sed 's/,$//')]
}
EOF
else
    print_header "Disk Usage Report"
    echo "Generated: $(date)"
    echo "Hostname:  $(hostname)"
    echo "Thresholds: Warning=${WARN_THRESHOLD}%, Critical=${CRIT_THRESHOLD}%"

    # Show alerts first
    if [[ ${#criticals[@]} -gt 0 ]]; then
        print_header "🚨 CRITICAL - Immediate Attention Required"
        for alert in "${criticals[@]}"; do
            echo "  $alert"
        done
    fi

    if [[ ${#warnings[@]} -gt 0 ]]; then
        print_header "⚠ Warnings"
        for alert in "${warnings[@]}"; do
            echo "  $alert"
        done
    fi

    print_header "Filesystem Usage"
    printf "%-20s %8s %8s %8s %6s  %s\n" "MOUNT" "SIZE" "USED" "AVAIL" "USE%" "STATUS"
    print_divider 65

    for entry in "${fs_data[@]}"; do
        IFS='|' read -r mount fs size used avail percent status <<< "$entry"

        # Status indicator
        case "$status" in
            critical) indicator="🚨" ;;
            warning)  indicator="⚠ " ;;
            *)        indicator="✓ " ;;
        esac

        printf "%-20s %8s %8s %8s %5s%%  %s\n" \
            "${mount:0:19}" "$size" "$used" "$avail" "$percent" "$indicator"
    done

    # Inode usage
    if $CHECK_INODES && [[ ${#inode_data[@]} -gt 0 ]]; then
        print_header "Inode Usage"
        printf "%-20s %12s %12s %12s %6s\n" "MOUNT" "INODES" "USED" "FREE" "USE%"
        print_divider 65

        for entry in "${inode_data[@]}"; do
            IFS='|' read -r mount inodes iused ifree percent status <<< "$entry"
            printf "%-20s %12s %12s %12s %5s%%\n" \
                "${mount:0:19}" "$inodes" "$iused" "$ifree" "$percent"
        done
    fi

    # Large directories
    print_header "Largest Directories (Top ${TOP_N})"
    echo "Scanning root filesystem..."
    echo ""

    large_dirs=$(get_large_dirs "/" "$TOP_N")
    if [[ -n "$large_dirs" ]]; then
        printf "%-10s  %s\n" "SIZE" "DIRECTORY"
        print_divider 50
        echo "$large_dirs" | while read -r size dir; do
            printf "%-10s  %s\n" "$size" "$dir"
        done
    else
        echo "  Could not scan directories (may need root access)"
    fi

    # Docker-specific disk usage hint
    if command -v docker &>/dev/null; then
        print_header "Docker Disk Usage"
        docker system df 2>/dev/null || echo "  Run 'docker system df' for Docker disk usage"
    fi

    print_divider
    case $exit_code in
        0) log_success "All filesystems within normal limits" ;;
        2) log_warn "Warning threshold exceeded on some filesystems" ;;
        3) log_error "CRITICAL threshold exceeded - action required!" ;;
    esac
fi

# Notify if configured
if [[ -n "${UPTIME_KUMA_DISK_PUSH:-}" ]]; then
    if [[ $exit_code -ge 2 ]]; then
        notify_uptime_kuma "$UPTIME_KUMA_DISK_PUSH" "down" "Disk usage alert: ${criticals[*]:-} ${warnings[*]:-}"
    else
        notify_uptime_kuma "$UPTIME_KUMA_DISK_PUSH" "up" "Disk usage normal"
    fi
fi

exit $exit_code
