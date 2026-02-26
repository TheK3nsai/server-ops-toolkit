#!/usr/bin/env bash
# system-updates.sh - Check and optionally apply system updates
#
# Purpose: Check for available dnf updates, show security updates,
#          and optionally apply updates with logging
#
# Usage: ./system-updates.sh [--check] [--apply] [--security-only] [--json]
#        --check         : Only check for updates (default)
#        --apply         : Apply available updates (requires sudo)
#        --security-only : Only show/apply security updates
#        --reboot-check  : Check if reboot is required
#        --json          : Output in JSON format
#
# Dependencies: dnf, needs-restarting (dnf-utils)
#
# Exit codes: 0=no updates/success, 1=error, 2=updates available

set -euo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../lib/common.sh"

# Configuration
CHECK_ONLY=true
SECURITY_ONLY=false
REBOOT_CHECK=false
JSON_OUTPUT=false
LOG_FILE="${LOG_DIR}/system-updates.log"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --check)
            CHECK_ONLY=true
            shift
            ;;
        --apply)
            CHECK_ONLY=false
            shift
            ;;
        --security-only)
            SECURITY_ONLY=true
            shift
            ;;
        --reboot-check)
            REBOOT_CHECK=true
            shift
            ;;
        --json)
            JSON_OUTPUT=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--check] [--apply] [--security-only] [--reboot-check] [--json]"
            echo ""
            echo "Options:"
            echo "  --check         : Only check for updates (default)"
            echo "  --apply         : Apply available updates (requires sudo)"
            echo "  --security-only : Only show/apply security updates"
            echo "  --reboot-check  : Check if reboot is required"
            echo "  --json          : Output in JSON format"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check dnf is available
if ! command -v dnf &>/dev/null; then
    log_error "dnf package manager not found"
    exit 1
fi

# Initialize tracking
declare -a available_updates=()
declare -a security_updates=()
reboot_required=false
exit_code=0

# Get OS info
os_name=$(cat /etc/redhat-release 2>/dev/null || echo "Unknown")
kernel_current=$(uname -r)

# Check for updates
log_info "Checking for available updates..."

# Get list of available updates
update_list=$(dnf check-update --quiet 2>/dev/null || true)
update_count=0

if [[ -n "$update_list" ]]; then
    while IFS= read -r line; do
        # Skip empty lines and metadata
        [[ -z "$line" ]] && continue
        [[ "$line" =~ ^Obsoleting ]] && continue
        [[ "$line" =~ ^Last\ metadata ]] && continue
        [[ "$line" =~ ^[[:space:]] ]] && continue

        # Parse package info: name.arch version repo
        pkg_name=$(echo "$line" | awk '{print $1}')
        pkg_version=$(echo "$line" | awk '{print $2}')
        pkg_repo=$(echo "$line" | awk '{print $3}')

        [[ -z "$pkg_name" ]] && continue

        available_updates+=("${pkg_name}|${pkg_version}|${pkg_repo}")
        ((update_count++))
    done <<< "$update_list"
fi

# Check for security updates specifically
if $SECURITY_ONLY || ! $JSON_OUTPUT; then
    security_list=$(dnf updateinfo list security --available 2>/dev/null || true)

    if [[ -n "$security_list" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            [[ "$line" =~ ^Last\ metadata ]] && continue

            # Parse: advisory severity package
            advisory=$(echo "$line" | awk '{print $1}')
            severity=$(echo "$line" | awk '{print $2}')
            pkg=$(echo "$line" | awk '{print $3}')

            [[ -z "$advisory" ]] && continue
            [[ "$advisory" == "advisory" ]] && continue  # Skip header
            # Skip repo name lines (e.g. "Docker CE Stable", "Rocky Linux 10")
            # Real advisories match patterns like RLSA-2026:1234, CVE-2026-12345
            [[ ! "$advisory" =~ -[0-9]{4}[:-] ]] && continue

            security_updates+=("${advisory}|${severity}|${pkg}")
        done <<< "$security_list"
    fi
fi

# Check if reboot is required
if $REBOOT_CHECK || ! $JSON_OUTPUT; then
    # Prefer dnf subcommand (available on RHEL/Rocky without standalone binary)
    nr_rc=0
    dnf needs-restarting -r &>/dev/null 2>&1 || nr_rc=$?
    if [[ $nr_rc -eq 0 ]]; then
        : # no reboot needed
    elif [[ $nr_rc -eq 1 ]]; then
        reboot_required=true
    else
        # Fallback: check if running kernel matches installed
        installed_kernel=$(rpm -q kernel --last 2>/dev/null | head -1 | awk '{print $1}' | sed 's/kernel-//')
        if [[ -n "$installed_kernel" ]] && [[ "$kernel_current" != "$installed_kernel" ]]; then
            reboot_required=true
        fi
    fi
fi

# Set exit code based on updates
if [[ $update_count -gt 0 ]]; then
    exit_code=2
fi

# Apply updates if requested
applied_count=0
if ! $CHECK_ONLY && [[ $update_count -gt 0 ]]; then
    if [[ $EUID -ne 0 ]]; then
        log_error "Must run with sudo to apply updates"
        exit 1
    fi

    log_info "Applying updates..."

    # Build dnf command
    dnf_cmd="dnf upgrade -y"
    if $SECURITY_ONLY; then
        dnf_cmd="dnf upgrade --security -y"
    fi

    # Run update with logging
    if $JSON_OUTPUT; then
        if $dnf_cmd >> "$LOG_FILE" 2>&1; then
            applied_count=$update_count
            exit_code=0
        else
            log_error "Update failed - check $LOG_FILE"
            exit_code=1
        fi
    else
        echo ""
        if $dnf_cmd 2>&1 | tee -a "$LOG_FILE"; then
            applied_count=$update_count
            exit_code=0
        else
            log_error "Update failed"
            exit_code=1
        fi
    fi

    # Re-check if reboot needed after updates
    nr_rc=0
    dnf needs-restarting -r &>/dev/null 2>&1 || nr_rc=$?
    if [[ $nr_rc -eq 1 ]]; then
        reboot_required=true
    fi
fi

# Output results
if $JSON_OUTPUT; then
    cat <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "os": "$os_name",
  "kernel": "$kernel_current",
  "mode": "$([ "$CHECK_ONLY" = true ] && echo "check" || echo "apply")",
  "summary": {
    "total_updates": $update_count,
    "security_updates": ${#security_updates[@]},
    "applied": $applied_count,
    "reboot_required": $reboot_required
  },
  "updates": [
$(first=true
for entry in "${available_updates[@]:-}"; do
    [[ -z "$entry" ]] && continue
    IFS='|' read -r name version repo <<< "$entry"
    $first || echo ","
    first=false
    printf '    {"package": "%s", "version": "%s", "repo": "%s"}' "$name" "$version" "$repo"
done)
  ],
  "security": [
$(first=true
for entry in "${security_updates[@]:-}"; do
    [[ -z "$entry" ]] && continue
    IFS='|' read -r advisory severity pkg <<< "$entry"
    $first || echo ","
    first=false
    printf '    {"advisory": "%s", "severity": "%s", "package": "%s"}' "$advisory" "$severity" "$pkg"
done)
  ]
}
EOF
else
    print_header "System Update Report"
    echo "Generated: $(date)"
    echo "Hostname:  $(hostname)"
    echo "OS:        $os_name"
    echo "Kernel:    $kernel_current"
    echo "Mode:      $([ "$CHECK_ONLY" = true ] && echo "Check only" || echo "Apply updates")"

    print_header "Summary"
    echo "Total updates available:    $update_count"
    echo "Security updates:           ${#security_updates[@]}"
    if ! $CHECK_ONLY; then
        echo "Updates applied:            $applied_count"
    fi

    if $reboot_required; then
        echo ""
        echo "⚠ REBOOT REQUIRED to complete updates"
    fi

    # Show security updates first
    if [[ ${#security_updates[@]} -gt 0 ]]; then
        print_header "🔒 Security Updates"
        printf "%-20s %-12s %s\n" "ADVISORY" "SEVERITY" "PACKAGE"
        print_divider 60

        for entry in "${security_updates[@]}"; do
            IFS='|' read -r advisory severity pkg <<< "$entry"
            printf "%-20s %-12s %s\n" "$advisory" "$severity" "$pkg"
        done
    fi

    # Show all updates
    if [[ $update_count -gt 0 ]] && [[ $update_count -le 50 ]]; then
        print_header "Available Updates"
        printf "%-40s %-20s %s\n" "PACKAGE" "VERSION" "REPO"
        print_divider 75

        for entry in "${available_updates[@]:-}"; do
            [[ -z "$entry" ]] && continue
            IFS='|' read -r name version repo <<< "$entry"
            printf "%-40s %-20s %s\n" "${name:0:39}" "${version:0:19}" "$repo"
        done
    elif [[ $update_count -gt 50 ]]; then
        print_header "Available Updates"
        echo "$update_count updates available (too many to list)"
        echo "Run 'dnf check-update' to see full list"
    fi

    # Services needing restart
    if [[ $EUID -eq 0 ]]; then
        services_restart=$(dnf needs-restarting -s 2>/dev/null || true)
        if [[ -n "$services_restart" ]]; then
            print_header "Services Needing Restart"
            echo "$services_restart" | head -20
        fi
    fi

    print_divider
    if [[ $update_count -eq 0 ]]; then
        log_success "System is up to date"
    elif $CHECK_ONLY; then
        log_info "$update_count update(s) available"
        echo "Run with --apply to install updates"
    else
        log_success "Updates applied successfully"
        if $reboot_required; then
            log_warn "Reboot required to complete updates"
        fi
    fi

    # Quick commands
    echo ""
    echo "Quick commands:"
    echo "  Check updates:     dnf check-update"
    echo "  Apply all:         sudo dnf upgrade -y"
    echo "  Security only:     sudo dnf upgrade --security -y"
    echo "  Check reboot:      needs-restarting -r"
    echo "  Restart services:  needs-restarting -s"
fi

# Notify if configured
if [[ -n "${UPTIME_KUMA_UPDATES_PUSH:-}" ]]; then
    if [[ ${#security_updates[@]} -gt 0 ]]; then
        notify_uptime_kuma "$UPTIME_KUMA_UPDATES_PUSH" "down" "${#security_updates[@]} security updates pending"
    elif [[ $update_count -gt 0 ]]; then
        notify_uptime_kuma "$UPTIME_KUMA_UPDATES_PUSH" "up" "$update_count updates available"
    else
        notify_uptime_kuma "$UPTIME_KUMA_UPDATES_PUSH" "up" "System up to date"
    fi
fi

exit $exit_code
