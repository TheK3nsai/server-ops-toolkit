#!/usr/bin/env bash
# common.sh - Shared functions for ops scripts
# Source this file: source "$(dirname "$0")/../lib/common.sh"

# Exit if not sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    echo "This script should be sourced, not executed directly." >&2
    exit 1
fi

# Load environment variables
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OPS_ROOT="$(dirname "$SCRIPT_DIR")"
CONF_DIR="${OPS_ROOT}/conf"
LOG_DIR="${OPS_ROOT}/logs"

if [[ -f "${CONF_DIR}/.env" ]]; then
    # shellcheck disable=SC1091
    source "${CONF_DIR}/.env"
fi

# Hostname for notifications
HOSTNAME_SHORT="$(hostname -s)"

# Logging functions
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp
    timestamp="$(date '+%Y-%m-%d %H:%M:%S')"
    echo "[${timestamp}] [${level}] ${message}"
}

log_info()    { log "INFO" "$@"; }
log_warn()    { log "WARN" "$@"; }
log_error()   { log "ERROR" "$@"; }
log_success() { log "OK" "$@"; }

# Logging to file (call with script name)
setup_logging() {
    local script_name="$1"
    local log_file="${LOG_DIR}/${script_name}.log"

    # Ensure log directory exists
    mkdir -p "${LOG_DIR}"

    # Redirect stdout and stderr to both console and log file
    exec > >(tee -a "${log_file}") 2>&1
}

# Notification functions
notify_uptime_kuma() {
    local push_url="$1"
    local status="${2:-up}"  # up, down
    local msg="${3:-}"
    local ping="${4:-}"

    if [[ -z "$push_url" ]]; then
        log_warn "No Uptime Kuma push URL provided"
        return 1
    fi

    local url="${push_url}?status=${status}"
    [[ -n "$msg" ]] && url="${url}&msg=$(printf '%s' "$msg" | jq -sRr @uri)"
    [[ -n "$ping" ]] && url="${url}&ping=${ping}"

    curl -fsS -m 10 "$url" >/dev/null 2>&1 || {
        log_warn "Failed to notify Uptime Kuma"
        return 1
    }
}

notify_email() {
    local subject="$1"
    local body="$2"
    local recipient="${3:-${ALERT_EMAIL:-root}}"

    if command -v mail &>/dev/null; then
        echo "$body" | mail -s "[${HOSTNAME_SHORT}] ${subject}" "$recipient"
    else
        log_warn "mail command not available, cannot send email"
        return 1
    fi
}

# Format notification message
format_alert() {
    local severity="$1"  # INFO, WARN, ERROR, CRITICAL
    local message="$2"
    echo "[${HOSTNAME_SHORT}] [${severity}] ${message}"
}

# Check if running as root
require_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

# Check if a command exists
require_command() {
    local cmd="$1"
    if ! command -v "$cmd" &>/dev/null; then
        log_error "Required command not found: $cmd"
        exit 1
    fi
}

# Check if a service is active
is_service_active() {
    local service="$1"
    systemctl is-active --quiet "$service"
}

# Get service status with color indicator
service_status() {
    local service="$1"
    if systemctl is-active --quiet "$service"; then
        echo "● $service: active"
        return 0
    else
        echo "○ $service: inactive"
        return 1
    fi
}

# Human-readable file sizes
human_size() {
    local bytes="$1"
    if [[ $bytes -ge 1073741824 ]]; then
        printf "%.2f GB" "$(echo "scale=2; $bytes/1073741824" | bc)"
    elif [[ $bytes -ge 1048576 ]]; then
        printf "%.2f MB" "$(echo "scale=2; $bytes/1048576" | bc)"
    elif [[ $bytes -ge 1024 ]]; then
        printf "%.2f KB" "$(echo "scale=2; $bytes/1024" | bc)"
    else
        printf "%d B" "$bytes"
    fi
}

# Date helpers
days_ago() {
    local days="$1"
    date -d "${days} days ago" '+%Y-%m-%d'
}

hours_ago() {
    local hours="$1"
    date -d "${hours} hours ago" '+%Y-%m-%d %H:%M:%S'
}

# Check if value exceeds threshold (returns 0 if exceeded)
exceeds_threshold() {
    local value="$1"
    local threshold="$2"
    (( value > threshold ))
}

# Print a section header
print_header() {
    local title="$1"
    local width="${2:-60}"
    local line
    line=$(printf '%*s' "$width" '' | tr ' ' '=')
    echo ""
    echo "$line"
    echo " $title"
    echo "$line"
}

# Print a divider
print_divider() {
    local width="${1:-60}"
    printf '%*s\n' "$width" '' | tr ' ' '-'
}
