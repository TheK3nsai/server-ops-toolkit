#!/usr/bin/env bash
# memory-swap-monitor.sh - Monitor memory and swap usage
#
# Purpose: Check system memory and swap usage against thresholds,
#          identify top memory-consuming processes, and detect OOM events
#
# Usage: ./memory-swap-monitor.sh [--json] [--quiet] [--top N] [--help]
#        --json    : Output in JSON format
#        --quiet   : Only output if thresholds exceeded (for cron)
#        --top N   : Show top N memory-consuming processes (default: 10)
#
# Dependencies: free, ps, journalctl (standard utils)
#
# Exit codes: 0=ok, 1=error, 2=warning threshold, 3=critical threshold

set -euo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../lib/common.sh"

# Configuration
MEM_WARN="${MEM_WARN_THRESHOLD:-80}"
MEM_CRIT="${MEM_CRIT_THRESHOLD:-90}"
SWAP_WARN="${SWAP_WARN_THRESHOLD:-50}"
JSON_OUTPUT=false
QUIET=false
TOP_N=10

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --json)
            JSON_OUTPUT=true
            shift
            ;;
        --quiet)
            QUIET=true
            shift
            ;;
        --top)
            TOP_N="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--json] [--quiet] [--top N]"
            echo "  --json    : Output in JSON format"
            echo "  --quiet   : Only output if thresholds exceeded"
            echo "  --top N   : Show top N memory-consuming processes (default: 10)"
            echo ""
            echo "Thresholds (set via env or conf/.env):"
            echo "  MEM_WARN_THRESHOLD=${MEM_WARN}%"
            echo "  MEM_CRIT_THRESHOLD=${MEM_CRIT}%"
            echo "  SWAP_WARN_THRESHOLD=${SWAP_WARN}%"
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

# Collect memory data (in bytes)
read -r mem_total mem_used mem_free mem_shared mem_buffers mem_available < <(
    free -b | awk '/^Mem:/{print $2, $3, $4, $5, $6, $7}'
)

# Effective usage = total - available
mem_effective_used=$((mem_total - mem_available))
if [[ $mem_total -gt 0 ]]; then
    mem_percent=$((mem_effective_used * 100 / mem_total))
else
    mem_percent=0
fi

# Collect swap data
read -r swap_total swap_used swap_free < <(
    free -b | awk '/^Swap:/{print $2, $3, $4}'
)

swap_percent=0
if [[ $swap_total -gt 0 ]]; then
    swap_percent=$((swap_used * 100 / swap_total))
fi

# Evaluate thresholds
mem_status="ok"
if [[ $mem_percent -ge $MEM_CRIT ]]; then
    mem_status="critical"
    criticals+=("Memory: ${mem_percent}%")
    [[ $exit_code -lt 3 ]] && exit_code=3
elif [[ $mem_percent -ge $MEM_WARN ]]; then
    mem_status="warning"
    warnings+=("Memory: ${mem_percent}%")
    [[ $exit_code -lt 2 ]] && exit_code=2
fi

swap_status="ok"
if [[ $swap_total -gt 0 ]] && [[ $swap_percent -ge $SWAP_WARN ]]; then
    swap_status="warning"
    warnings+=("Swap: ${swap_percent}%")
    [[ $exit_code -lt 2 ]] && exit_code=2
fi

# Top memory processes
declare -a top_procs=()
while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    top_procs+=("$line")
done < <(ps -eo pid,user,%mem,rss,comm --sort=-%mem --no-headers 2>/dev/null | head -n "$TOP_N")

# OOM events (last 24h)
oom_count=0
declare -a oom_events=()
if command -v journalctl &>/dev/null; then
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        oom_events+=("$line")
        ((oom_count++)) || true
    done < <(journalctl -k --since "24 hours ago" --no-pager -q 2>/dev/null | grep -i "oom-kill\|out of memory" || true)
fi

if [[ $oom_count -gt 0 ]]; then
    criticals+=("OOM kills: ${oom_count} in last 24h")
    [[ $exit_code -lt 3 ]] && exit_code=3
fi

# Output results
if $JSON_OUTPUT; then
    cat <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "thresholds": {
    "mem_warn": $MEM_WARN,
    "mem_crit": $MEM_CRIT,
    "swap_warn": $SWAP_WARN
  },
  "status": "$([ $exit_code -eq 0 ] && echo "ok" || ([ $exit_code -eq 2 ] && echo "warning" || echo "critical"))",
  "memory": {
    "total_bytes": $mem_total,
    "used_bytes": $mem_effective_used,
    "available_bytes": $mem_available,
    "buffers_bytes": $mem_buffers,
    "percent": $mem_percent,
    "status": "$mem_status"
  },
  "swap": {
    "total_bytes": $swap_total,
    "used_bytes": $swap_used,
    "free_bytes": $swap_free,
    "percent": $swap_percent,
    "status": "$swap_status"
  },
  "oom_events_24h": $oom_count,
  "top_processes": [
$(first=true
for proc in "${top_procs[@]}"; do
    read -r pid user mem_pct rss comm <<< "$proc"
    $first || echo ","
    first=false
    printf '    {"pid": %s, "user": "%s", "mem_percent": "%s", "rss_kb": %s, "command": "%s"}' \
        "$pid" "$user" "$mem_pct" "$rss" "$comm"
done)
  ],
  "warnings": [$(if [[ ${#warnings[@]} -gt 0 ]]; then printf '"%s",' "${warnings[@]}" | sed 's/,$//'; fi)],
  "criticals": [$(if [[ ${#criticals[@]} -gt 0 ]]; then printf '"%s",' "${criticals[@]}" | sed 's/,$//'; fi)]
}
EOF
else
    # Human-readable output
    if ! $QUIET || [[ $exit_code -ge 2 ]]; then
        print_header "Memory & Swap Monitor"
        echo "Generated: $(date)"
        echo "Hostname:  $(hostname)"
        echo "Thresholds: Mem Warning=${MEM_WARN}%, Mem Critical=${MEM_CRIT}%, Swap Warning=${SWAP_WARN}%"

        # Show alerts first
        if [[ ${#criticals[@]} -gt 0 ]]; then
            print_header "CRITICAL"
            for alert in "${criticals[@]}"; do
                echo "  $alert"
            done
        fi

        if [[ ${#warnings[@]} -gt 0 ]]; then
            print_header "Warnings"
            for alert in "${warnings[@]}"; do
                echo "  $alert"
            done
        fi

        print_header "Memory Usage"
        printf "%-15s %12s\n" "Total:" "$(human_size "$mem_total")"
        printf "%-15s %12s\n" "Used:" "$(human_size "$mem_effective_used")"
        printf "%-15s %12s\n" "Available:" "$(human_size "$mem_available")"
        printf "%-15s %11s%%\n" "Usage:" "$mem_percent"
        printf "%-15s %12s\n" "Status:" "$mem_status"

        print_header "Swap Usage"
        if [[ $swap_total -gt 0 ]]; then
            printf "%-15s %12s\n" "Total:" "$(human_size "$swap_total")"
            printf "%-15s %12s\n" "Used:" "$(human_size "$swap_used")"
            printf "%-15s %12s\n" "Free:" "$(human_size "$swap_free")"
            printf "%-15s %11s%%\n" "Usage:" "$swap_percent"
            printf "%-15s %12s\n" "Status:" "$swap_status"
        else
            echo "  No swap configured"
        fi

        print_header "Top ${TOP_N} Memory Processes"
        printf "%-8s %-12s %6s %12s  %s\n" "PID" "USER" "MEM%" "RSS" "COMMAND"
        print_divider 55
        for proc in "${top_procs[@]}"; do
            read -r pid user mem_pct rss comm <<< "$proc"
            printf "%-8s %-12s %5s%% %10sK  %s\n" "$pid" "$user" "$mem_pct" "$rss" "$comm"
        done

        if [[ $oom_count -gt 0 ]]; then
            print_header "OOM Events (Last 24h)"
            printf '%s\n' "${oom_events[@]}"
        fi

        print_divider
        case $exit_code in
            0) log_success "Memory and swap within normal limits" ;;
            2) log_warn "Warning threshold exceeded" ;;
            3) log_error "CRITICAL threshold exceeded - action required!" ;;
        esac
    fi
fi

# Notify if configured
if [[ -n "${UPTIME_KUMA_MEMORY_PUSH:-}" ]]; then
    if [[ $exit_code -ge 2 ]]; then
        notify_uptime_kuma "$UPTIME_KUMA_MEMORY_PUSH" "down" "Memory alert: ${criticals[*]:-} ${warnings[*]:-}"
    else
        notify_uptime_kuma "$UPTIME_KUMA_MEMORY_PUSH" "up" "Memory usage normal"
    fi
fi

exit $exit_code
