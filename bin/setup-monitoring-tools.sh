#!/usr/bin/env bash
# setup-monitoring-tools.sh - Configure monitoring tools (fail2ban, sysstat, logwatch)
#
# Purpose: Install configurations and enable services for monitoring tools
#
# Usage: sudo ./setup-monitoring-tools.sh [--check] [--apply]
#        --check : Only check current status (default)
#        --apply : Apply configurations and enable services
#
# Dependencies: fail2ban, sysstat, logwatch (must be installed)
#
# Exit codes: 0=success, 1=error, 2=needs configuration

set -euo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../lib/common.sh"

# Configuration
CHECK_ONLY=true
CONF_DIR="${SCRIPT_DIR}/../conf"

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
        -h|--help)
            echo "Usage: sudo $0 [--check] [--apply]"
            echo ""
            echo "Options:"
            echo "  --check : Only check current status (default)"
            echo "  --apply : Apply configurations and enable services"
            echo ""
            echo "This script configures:"
            echo "  - fail2ban: Enable sshd jail, recidive jail"
            echo "  - sysstat: Enable system activity data collection"
            echo "  - logwatch: Configure daily log analysis"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (use sudo)"
    exit 1
fi

needs_config=0

print_header "Monitoring Tools Configuration"
echo "Mode: $($CHECK_ONLY && echo "Check only" || echo "Apply changes")"

# ============================================================================
# fail2ban
# ============================================================================
print_header "1. fail2ban"

if ! command -v fail2ban-client &>/dev/null; then
    log_error "fail2ban is not installed"
    echo "Install with: sudo dnf install -y fail2ban fail2ban-firewalld"
    needs_config=1
else
    # Check service status
    if systemctl is-active --quiet fail2ban; then
        log_success "Service: active"
    else
        log_warn "Service: inactive"
        needs_config=1
        if ! $CHECK_ONLY; then
            systemctl start fail2ban
            systemctl enable fail2ban
            log_success "Started and enabled fail2ban"
        fi
    fi

    # Check jails
    jail_count=$(fail2ban-client status 2>/dev/null | grep "Number of jail:" | awk '{print $NF}' || echo "0")
    echo "Active jails: $jail_count"

    if [[ "$jail_count" -eq 0 ]]; then
        log_warn "No jails are enabled!"
        needs_config=1
    else
        fail2ban-client status 2>/dev/null | grep "Jail list:" | sed 's/.*Jail list:/  Jails:/'
    fi

    # Check for our config
    if [[ -f /etc/fail2ban/jail.d/local.conf ]]; then
        log_success "Custom config: /etc/fail2ban/jail.d/local.conf exists"
    else
        log_warn "Custom config not installed"
        needs_config=1

        if ! $CHECK_ONLY && [[ -f "${CONF_DIR}/fail2ban-local.conf" ]]; then
            cp "${CONF_DIR}/fail2ban-local.conf" /etc/fail2ban/jail.d/local.conf
            log_success "Installed fail2ban configuration"
            systemctl restart fail2ban
            log_success "Restarted fail2ban"
        else
            echo "  Config available at: ${CONF_DIR}/fail2ban-local.conf"
            echo "  Install with: sudo cp ${CONF_DIR}/fail2ban-local.conf /etc/fail2ban/jail.d/local.conf"
        fi
    fi

    # Show sshd jail status if active
    if fail2ban-client status sshd &>/dev/null; then
        echo ""
        echo "sshd jail status:"
        fail2ban-client status sshd | grep -E "Currently|Total" | sed 's/^/  /'
    fi
fi

# ============================================================================
# sysstat
# ============================================================================
print_header "2. sysstat"

if ! command -v sar &>/dev/null; then
    log_error "sysstat is not installed"
    echo "Install with: sudo dnf install -y sysstat"
    needs_config=1
else
    # Check service status
    if systemctl is-active --quiet sysstat; then
        log_success "Service: active"
    else
        log_warn "Service: inactive (no data collection)"
        needs_config=1

        if ! $CHECK_ONLY; then
            systemctl enable --now sysstat
            log_success "Enabled and started sysstat"
        else
            echo "  Enable with: sudo systemctl enable --now sysstat"
        fi
    fi

    # Check for data
    if [[ -d /var/log/sa ]] && ls /var/log/sa/sa* &>/dev/null; then
        data_files=$(ls /var/log/sa/sa* 2>/dev/null | wc -l)
        log_success "Data collection: $data_files data files in /var/log/sa/"
    else
        log_warn "No data collected yet"
        echo "  Data will be collected by cron after sysstat is enabled"
    fi

    # Show retention setting
    retention=$(grep "^HISTORY=" /etc/sysconfig/sysstat 2>/dev/null | cut -d= -f2 || echo "28")
    echo "Data retention: $retention days"
fi

# ============================================================================
# logwatch
# ============================================================================
print_header "3. logwatch"

if ! command -v logwatch &>/dev/null; then
    log_error "logwatch is not installed"
    echo "Install with: sudo dnf install -y logwatch"
    needs_config=1
else
    log_success "Installed: $(logwatch --version 2>&1 | head -1)"

    # Check for custom config
    if [[ -f /etc/logwatch/conf/logwatch.conf ]] && \
       grep -qv "^#" /etc/logwatch/conf/logwatch.conf 2>/dev/null | grep -q .; then
        log_success "Custom config: configured"
    else
        log_warn "Using default configuration"

        if ! $CHECK_ONLY && [[ -f "${CONF_DIR}/logwatch.conf" ]]; then
            cp "${CONF_DIR}/logwatch.conf" /etc/logwatch/conf/logwatch.conf
            log_success "Installed logwatch configuration"
        else
            echo "  Config available at: ${CONF_DIR}/logwatch.conf"
            echo "  Install with: sudo cp ${CONF_DIR}/logwatch.conf /etc/logwatch/conf/logwatch.conf"
        fi
    fi

    # Check cron
    if [[ -f /etc/cron.daily/0logwatch ]] || [[ -f /etc/cron.daily/logwatch ]]; then
        log_success "Cron job: daily execution configured"
    else
        log_warn "No daily cron job found"
    fi

    echo ""
    echo "Manual run commands:"
    echo "  Today's report:     sudo logwatch --detail High --range today"
    echo "  Yesterday's report: sudo logwatch --detail High --range yesterday"
fi

# ============================================================================
# Summary
# ============================================================================
print_header "Summary"

if [[ $needs_config -eq 0 ]]; then
    log_success "All monitoring tools are properly configured"
else
    if $CHECK_ONLY; then
        log_warn "Some tools need configuration"
        echo ""
        echo "Run with --apply to automatically configure:"
        echo "  sudo $0 --apply"
    else
        echo ""
        log_success "Configuration applied"
        echo "Verify with: $0 --check"
    fi
fi

exit $needs_config
