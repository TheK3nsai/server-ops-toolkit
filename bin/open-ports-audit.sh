#!/usr/bin/env bash
# open-ports-audit.sh - Audit open ports and compare with firewall rules
#
# Purpose: List all listening ports, compare with firewalld rules,
#          identify unexpected services, and flag potential issues
#
# Usage: ./open-ports-audit.sh [--json] [--allowed-file PATH]
#        --json          : Output in JSON format
#        --allowed-file  : Path to file listing expected ports (one per line)
#
# Dependencies: ss, firewall-cmd (firewalld), lsof (optional, for process info)
#
# Exit codes: 0=clean, 1=error, 2=unexpected ports found

set -euo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../lib/common.sh"

# Configuration
JSON_OUTPUT=false
ALLOWED_FILE="${CONF_DIR}/allowed-ports.conf"

# Default allowed ports (common services)
DEFAULT_ALLOWED_PORTS=(
    "22"    # SSH
    "80"    # HTTP
    "443"   # HTTPS
)

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --json)
            JSON_OUTPUT=true
            shift
            ;;
        --allowed-file)
            ALLOWED_FILE="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--json] [--allowed-file PATH]"
            echo "  --json          : Output in JSON format"
            echo "  --allowed-file  : Path to allowed ports config"
            echo ""
            echo "Allowed ports file format (one per line):"
            echo "  22/tcp      # SSH"
            echo "  80/tcp      # HTTP"
            echo "  443/tcp     # HTTPS"
            echo "  53/udp      # DNS"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Load allowed ports
declare -A allowed_ports=()
for port in "${DEFAULT_ALLOWED_PORTS[@]}"; do
    allowed_ports["${port}/tcp"]=1
done

if [[ -f "$ALLOWED_FILE" ]]; then
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^#.*$ ]] && continue
        [[ -z "${line// /}" ]] && continue
        # Extract port/proto (ignore comments after)
        port_spec=$(echo "$line" | awk '{print $1}')
        [[ -n "$port_spec" ]] && allowed_ports["$port_spec"]=1
    done < "$ALLOWED_FILE"
fi

# Function to get process info for a port (requires root/lsof)
get_process_info() {
    local port="$1"
    local proto="$2"

    if command -v lsof &>/dev/null && [[ $EUID -eq 0 ]]; then
        lsof -i "${proto}:${port}" -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {print $1"("$2")"}' | head -1
    elif command -v ss &>/dev/null; then
        ss -tlnp 2>/dev/null | grep ":${port} " | grep -oP 'users:\(\("\K[^"]+' | head -1
    else
        echo "unknown"
    fi
}

# Collect listening ports using ss
declare -A listening_ports=()
while IFS= read -r line; do
    # Parse ss output: State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
    local_addr=$(echo "$line" | awk '{print $4}')
    port=$(echo "$local_addr" | rev | cut -d: -f1 | rev)
    proto="tcp"

    # Skip if not a valid port number
    [[ "$port" =~ ^[0-9]+$ ]] || continue

    # Get the address part
    addr=$(echo "$local_addr" | rev | cut -d: -f2- | rev)

    # Get process if available
    process=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' || echo "unknown")

    listening_ports["${port}/tcp"]="${addr}|${process}"
done < <(ss -tlnH 2>/dev/null)

# Also check UDP
while IFS= read -r line; do
    local_addr=$(echo "$line" | awk '{print $4}')
    port=$(echo "$local_addr" | rev | cut -d: -f1 | rev)

    [[ "$port" =~ ^[0-9]+$ ]] || continue

    addr=$(echo "$local_addr" | rev | cut -d: -f2- | rev)
    process=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' || echo "unknown")

    listening_ports["${port}/udp"]="${addr}|${process}"
done < <(ss -ulnH 2>/dev/null)

# Get firewalld open ports
declare -A firewall_ports=()
if systemctl is-active --quiet firewalld; then
    firewalld_active=true

    # Get default zone
    default_zone=$(firewall-cmd --get-default-zone 2>/dev/null)

    # Get ports in default zone
    while IFS= read -r port_spec; do
        [[ -n "$port_spec" ]] && firewall_ports["$port_spec"]=1
    done < <(firewall-cmd --zone="$default_zone" --list-ports 2>/dev/null | tr ' ' '\n')

    # Get services and their ports
    while IFS= read -r service; do
        [[ -z "$service" ]] && continue
        # Get ports for this service
        service_ports=$(firewall-cmd --service="$service" --get-ports 2>/dev/null | tr ' ' '\n')
        for sp in $service_ports; do
            [[ -n "$sp" ]] && firewall_ports["$sp"]="service:$service"
        done

        # Also check well-known service ports
        case "$service" in
            ssh)   firewall_ports["22/tcp"]="service:ssh" ;;
            http)  firewall_ports["80/tcp"]="service:http" ;;
            https) firewall_ports["443/tcp"]="service:https" ;;
            dns)   firewall_ports["53/tcp"]="service:dns"; firewall_ports["53/udp"]="service:dns" ;;
        esac
    done < <(firewall-cmd --zone="$default_zone" --list-services 2>/dev/null | tr ' ' '\n')
else
    firewalld_active=false
    default_zone="N/A"
fi

# Analyze: find unexpected ports
declare -A unexpected_ports=()
declare -A expected_ports=()
issues_found=0

for port_spec in "${!listening_ports[@]}"; do
    port="${port_spec%/*}"

    # Skip localhost-only bindings
    addr_info="${listening_ports[$port_spec]}"
    addr="${addr_info%|*}"
    if [[ "$addr" == "127.0.0.1" ]] || [[ "$addr" == "::1" ]] || [[ "$addr" == "[::1]" ]]; then
        continue
    fi

    # Check if port is in allowed list or firewall
    if [[ -n "${allowed_ports[$port_spec]:-}" ]] || [[ -n "${firewall_ports[$port_spec]:-}" ]]; then
        expected_ports["$port_spec"]="${listening_ports[$port_spec]}"
    else
        unexpected_ports["$port_spec"]="${listening_ports[$port_spec]}"
        issues_found=1
    fi
done

# Check for firewall ports without listeners (misconfiguration?)
declare -A orphan_firewall_ports=()
for port_spec in "${!firewall_ports[@]}"; do
    if [[ -z "${listening_ports[$port_spec]:-}" ]]; then
        orphan_firewall_ports["$port_spec"]="${firewall_ports[$port_spec]}"
    fi
done

# Output
if $JSON_OUTPUT; then
    cat <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "firewalld": {
    "active": $firewalld_active,
    "default_zone": "$default_zone"
  },
  "summary": {
    "total_listening": ${#listening_ports[@]},
    "expected_ports": ${#expected_ports[@]},
    "unexpected_ports": ${#unexpected_ports[@]},
    "orphan_firewall_rules": ${#orphan_firewall_ports[@]}
  },
  "listening_ports": {
$(first=true; for p in "${!listening_ports[@]}"; do
    $first || echo ","
    first=false
    info="${listening_ports[$p]}"
    addr="${info%|*}"
    proc="${info#*|}"
    printf '    "%s": {"address": "%s", "process": "%s"}' "$p" "$addr" "$proc"
done)
  },
  "unexpected_ports": [$(printf '"%s",' "${!unexpected_ports[@]}" | sed 's/,$//')],
  "issues_found": $([ $issues_found -eq 1 ] && echo "true" || echo "false")
}
EOF
else
    print_header "Open Ports Audit"
    echo "Generated:     $(date)"
    echo "Firewalld:     $([ "$firewalld_active" = true ] && echo "active" || echo "inactive")"
    echo "Default zone:  $default_zone"
    echo "Allowed file:  $ALLOWED_FILE"

    print_header "Summary"
    echo "Total listening ports:   ${#listening_ports[@]}"
    echo "Expected/allowed:        ${#expected_ports[@]}"
    echo "Unexpected:              ${#unexpected_ports[@]}"
    echo "Orphan firewall rules:   ${#orphan_firewall_ports[@]}"

    print_header "Listening Ports (Non-Localhost)"
    printf "%-12s %-20s %-20s %s\n" "PORT" "ADDRESS" "PROCESS" "STATUS"
    print_divider 70

    for port_spec in $(echo "${!listening_ports[@]}" | tr ' ' '\n' | sort -t/ -k1 -n); do
        info="${listening_ports[$port_spec]}"
        addr="${info%|*}"
        proc="${info#*|}"

        # Skip localhost
        [[ "$addr" == "127.0.0.1" ]] || [[ "$addr" == "::1" ]] || [[ "$addr" == "[::1]" ]] && continue

        if [[ -n "${unexpected_ports[$port_spec]:-}" ]]; then
            status="⚠ UNEXPECTED"
        else
            status="✓ OK"
        fi

        printf "%-12s %-20s %-20s %s\n" "$port_spec" "$addr" "${proc:0:20}" "$status"
    done

    if [[ ${#unexpected_ports[@]} -gt 0 ]]; then
        print_header "⚠ Unexpected Ports Detail"
        echo "The following ports are listening but not in allowed list or firewall:"
        echo ""
        for port_spec in "${!unexpected_ports[@]}"; do
            info="${unexpected_ports[$port_spec]}"
            addr="${info%|*}"
            proc="${info#*|}"
            echo "  $port_spec"
            echo "    Address: $addr"
            echo "    Process: $proc"
            echo ""
        done
        echo "Actions:"
        echo "  - If expected: Add to $ALLOWED_FILE"
        echo "  - If unexpected: Investigate the service"
        echo "  - To close: sudo firewall-cmd --remove-port=PORT/PROTO --permanent"
    fi

    if [[ ${#orphan_firewall_ports[@]} -gt 0 ]]; then
        print_header "⚠ Orphan Firewall Rules"
        echo "Firewall allows these ports, but nothing is listening:"
        for port_spec in "${!orphan_firewall_ports[@]}"; do
            printf "  %-12s (%s)\n" "$port_spec" "${orphan_firewall_ports[$port_spec]}"
        done
        echo ""
        echo "This may be intentional (service not running) or stale rules."
    fi

    print_header "Firewall Quick Reference"
    echo "List all ports:    firewall-cmd --list-ports"
    echo "List services:     firewall-cmd --list-services"
    echo "Add port:          firewall-cmd --add-port=PORT/PROTO --permanent"
    echo "Remove port:       firewall-cmd --remove-port=PORT/PROTO --permanent"
    echo "Reload:            firewall-cmd --reload"

    print_divider
    if [[ $issues_found -eq 1 ]]; then
        log_warn "Unexpected ports detected - review above"
    else
        log_success "All listening ports are expected"
    fi
fi

# Notify if configured
if [[ -n "${UPTIME_KUMA_PORTS_PUSH:-}" ]]; then
    if [[ $issues_found -eq 1 ]]; then
        notify_uptime_kuma "$UPTIME_KUMA_PORTS_PUSH" "down" "${#unexpected_ports[@]} unexpected ports"
    else
        notify_uptime_kuma "$UPTIME_KUMA_PORTS_PUSH" "up" "${#listening_ports[@]} ports, all expected"
    fi
fi

exit $((issues_found * 2))
