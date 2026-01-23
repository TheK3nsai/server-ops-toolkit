#!/usr/bin/env bash
# container-resource-report.sh - Report Docker container resource usage
#
# Purpose: Show CPU, memory, network, and disk usage for all containers
#          with sorting and threshold alerting options
#
# Usage: ./container-resource-report.sh [--sort FIELD] [--json] [--top N]
#        --sort FIELD : Sort by cpu, mem, net, or name (default: mem)
#        --json       : Output in JSON format
#        --top N      : Only show top N containers (default: all)
#        --alert      : Only show containers exceeding thresholds
#
# Dependencies: docker
#
# Exit codes: 0=normal, 1=error, 2=thresholds exceeded

set -euo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../lib/common.sh"

# Configuration
SORT_BY="mem"
JSON_OUTPUT=false
TOP_N=0  # 0 = show all
ALERT_ONLY=false
MEM_WARN_PERCENT="${CONTAINER_MEM_WARN:-80}"
CPU_WARN_PERCENT="${CONTAINER_CPU_WARN:-90}"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --sort)
            SORT_BY="$2"
            shift 2
            ;;
        --json)
            JSON_OUTPUT=true
            shift
            ;;
        --top)
            TOP_N="$2"
            shift 2
            ;;
        --alert)
            ALERT_ONLY=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--sort FIELD] [--json] [--top N] [--alert]"
            echo "  --sort FIELD : Sort by cpu, mem, net, or name (default: mem)"
            echo "  --json       : Output in JSON format"
            echo "  --top N      : Only show top N containers"
            echo "  --alert      : Only show containers exceeding thresholds"
            echo ""
            echo "Thresholds (set via env or conf/.env):"
            echo "  CONTAINER_MEM_WARN=${MEM_WARN_PERCENT}%"
            echo "  CONTAINER_CPU_WARN=${CPU_WARN_PERCENT}%"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check Docker is available
if ! docker info &>/dev/null; then
    log_error "Cannot connect to Docker daemon"
    exit 1
fi

# Get docker stats (one-shot, no stream)
# Format: Name, CPU%, MemUsage, MemLimit, Mem%, NetIO, BlockIO, PIDs
stats_output=$(docker stats --no-stream --format "{{.Name}}|{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}|{{.NetIO}}|{{.BlockIO}}|{{.PIDs}}" 2>/dev/null)

if [[ -z "$stats_output" ]]; then
    log_warn "No running containers found"
    exit 0
fi

# Parse stats into arrays
declare -a container_data=()
declare -a alert_containers=()
issues_found=0

while IFS='|' read -r name cpu mem_usage mem_perc net_io block_io pids; do
    # Clean up percentages (remove % sign)
    cpu_num="${cpu%\%}"
    mem_num="${mem_perc%\%}"

    # Check thresholds
    alert=""
    if (( $(echo "$cpu_num > $CPU_WARN_PERCENT" | bc -l 2>/dev/null || echo 0) )); then
        alert="cpu"
        issues_found=1
    fi
    if (( $(echo "$mem_num > $MEM_WARN_PERCENT" | bc -l 2>/dev/null || echo 0) )); then
        [[ -n "$alert" ]] && alert="${alert},mem" || alert="mem"
        issues_found=1
    fi

    # Store data
    container_data+=("${name}|${cpu}|${mem_usage}|${mem_perc}|${net_io}|${block_io}|${pids}|${alert}")

    if [[ -n "$alert" ]]; then
        alert_containers+=("${name}|${alert}")
    fi
done <<< "$stats_output"

# Sort data
case "$SORT_BY" in
    cpu)
        # Sort by CPU percentage descending
        sorted_data=$(printf '%s\n' "${container_data[@]}" | sort -t'|' -k2 -rn)
        ;;
    mem)
        # Sort by memory percentage descending
        sorted_data=$(printf '%s\n' "${container_data[@]}" | sort -t'|' -k4 -rn)
        ;;
    net)
        # Sort by name for now (network is harder to sort)
        sorted_data=$(printf '%s\n' "${container_data[@]}" | sort -t'|' -k1)
        ;;
    name)
        sorted_data=$(printf '%s\n' "${container_data[@]}" | sort -t'|' -k1)
        ;;
    *)
        sorted_data=$(printf '%s\n' "${container_data[@]}")
        ;;
esac

# Apply top N filter
if [[ $TOP_N -gt 0 ]]; then
    sorted_data=$(echo "$sorted_data" | head -n "$TOP_N")
fi

# Get system totals
total_containers=$(docker ps -q | wc -l)
system_mem=$(free -b | awk '/^Mem:/{print $2}')
system_mem_used=$(free -b | awk '/^Mem:/{print $3}')
system_mem_perc=$((system_mem_used * 100 / system_mem))

# Get Docker disk usage
docker_disk=$(docker system df --format "{{.Type}}\t{{.Size}}\t{{.Reclaimable}}" 2>/dev/null)

# Output results
if $JSON_OUTPUT; then
    echo "{"
    echo "  \"timestamp\": \"$(date -Iseconds)\","
    echo "  \"system\": {"
    echo "    \"total_containers\": $total_containers,"
    echo "    \"memory_percent\": $system_mem_perc"
    echo "  },"
    echo "  \"thresholds\": {"
    echo "    \"cpu_warn\": $CPU_WARN_PERCENT,"
    echo "    \"mem_warn\": $MEM_WARN_PERCENT"
    echo "  },"
    echo "  \"alerts\": ${#alert_containers[@]},"
    echo "  \"containers\": ["

    first=true
    while IFS='|' read -r name cpu mem_usage mem_perc net_io block_io pids alert; do
        [[ -z "$name" ]] && continue
        if $ALERT_ONLY && [[ -z "$alert" ]]; then
            continue
        fi

        $first || echo ","
        first=false

        cat <<CONTAINER
    {
      "name": "$name",
      "cpu_percent": "${cpu%\%}",
      "memory_usage": "$mem_usage",
      "memory_percent": "${mem_perc%\%}",
      "network_io": "$net_io",
      "block_io": "$block_io",
      "pids": "$pids",
      "alert": "$alert"
    }
CONTAINER
    done <<< "$sorted_data"

    echo ""
    echo "  ]"
    echo "}"
else
    print_header "Container Resource Report"
    echo "Generated: $(date)"
    echo "Sort by: $SORT_BY"

    print_header "System Overview"
    echo "Running containers: $total_containers"
    echo "System memory:      ${system_mem_perc}% used"
    echo "Alert thresholds:   CPU >${CPU_WARN_PERCENT}%, Memory >${MEM_WARN_PERCENT}%"

    # Show alerts first if any
    if [[ ${#alert_containers[@]} -gt 0 ]]; then
        print_header "⚠ Containers Exceeding Thresholds"
        for entry in "${alert_containers[@]}"; do
            IFS='|' read -r name alerts <<< "$entry"
            echo "  $name: $alerts"
        done
    fi

    print_header "Resource Usage"
    printf "%-22s %8s %20s %8s %8s\n" "CONTAINER" "CPU" "MEMORY" "MEM%" "PIDS"
    print_divider 70

    while IFS='|' read -r name cpu mem_usage mem_perc net_io block_io pids alert; do
        [[ -z "$name" ]] && continue
        if $ALERT_ONLY && [[ -z "$alert" ]]; then
            continue
        fi

        # Add indicator for alerts
        indicator=""
        [[ -n "$alert" ]] && indicator="⚠"

        printf "%-22s %8s %20s %8s %8s %s\n" \
            "${name:0:21}" "$cpu" "${mem_usage:0:19}" "$mem_perc" "$pids" "$indicator"
    done <<< "$sorted_data"

    print_header "Network I/O"
    printf "%-25s %25s\n" "CONTAINER" "NET I/O (RX / TX)"
    print_divider 55

    while IFS='|' read -r name cpu mem_usage mem_perc net_io block_io pids alert; do
        [[ -z "$name" ]] && continue
        if $ALERT_ONLY && [[ -z "$alert" ]]; then
            continue
        fi
        printf "%-25s %25s\n" "${name:0:24}" "$net_io"
    done <<< "$sorted_data"

    print_header "Block I/O"
    printf "%-25s %25s\n" "CONTAINER" "BLOCK I/O (R / W)"
    print_divider 55

    while IFS='|' read -r name cpu mem_usage mem_perc net_io block_io pids alert; do
        [[ -z "$name" ]] && continue
        if $ALERT_ONLY && [[ -z "$alert" ]]; then
            continue
        fi
        printf "%-25s %25s\n" "${name:0:24}" "$block_io"
    done <<< "$sorted_data"

    print_header "Docker Disk Usage"
    echo "$docker_disk" | while IFS=$'\t' read -r type size reclaimable; do
        printf "%-15s Size: %-12s Reclaimable: %s\n" "$type" "$size" "$reclaimable"
    done

    print_divider
    if [[ $issues_found -eq 1 ]]; then
        log_warn "${#alert_containers[@]} container(s) exceeding thresholds"
    else
        log_success "All containers within normal limits"
    fi
fi

# Notify if configured and issues found
if [[ $issues_found -eq 1 ]] && [[ -n "${UPTIME_KUMA_RESOURCES_PUSH:-}" ]]; then
    notify_uptime_kuma "$UPTIME_KUMA_RESOURCES_PUSH" "down" "${#alert_containers[@]} containers over threshold"
elif [[ -n "${UPTIME_KUMA_RESOURCES_PUSH:-}" ]]; then
    notify_uptime_kuma "$UPTIME_KUMA_RESOURCES_PUSH" "up" "Resources normal"
fi

exit $((issues_found * 2))
