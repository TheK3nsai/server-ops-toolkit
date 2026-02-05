#!/usr/bin/env bash
# access-audit-report.sh - Generate comprehensive access audit report
#
# Purpose: Create audit reports for compliance (HIPAA, IRS 4557, SOC2 awareness)
#          covering user access, sudo usage, file access, and system changes
#
# Usage: ./access-audit-report.sh [--days N] [--output FILE] [--json] [--full]
#        --days N      : Report period in days (default: 30)
#        --output FILE : Write report to file (default: stdout)
#        --json        : Output in JSON format
#        --full        : Include detailed logs (verbose)
#
# Dependencies: last, lastlog, aureport (audit), sudo access to some logs
#
# Exit codes: 0=success, 1=error, 2=findings require attention

set -euo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../lib/common.sh"

# Configuration
REPORT_DAYS="${AUDIT_REPORT_DAYS:-30}"
OUTPUT_FILE=""
JSON_OUTPUT=false
FULL_REPORT=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --days)
            REPORT_DAYS="$2"
            shift 2
            ;;
        --output)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        --json)
            JSON_OUTPUT=true
            shift
            ;;
        --full)
            FULL_REPORT=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--days N] [--output FILE] [--json] [--full]"
            echo ""
            echo "Options:"
            echo "  --days N      : Report period in days (default: 30)"
            echo "  --output FILE : Write report to file"
            echo "  --json        : Output in JSON format"
            echo "  --full        : Include detailed logs"
            echo ""
            echo "Generates compliance-focused audit report including:"
            echo "  - User account inventory"
            echo "  - Login activity summary"
            echo "  - Sudo/privilege escalation events"
            echo "  - Failed authentication attempts"
            echo "  - SSH key inventory"
            echo "  - System configuration changes"
            echo "  - Security posture (SELinux, firewall, kernel hardening)"
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

# Track findings
findings_count=0
declare -a findings=()

add_finding() {
    local severity="$1"
    local message="$2"
    findings+=("[$severity] $message")
    ((findings_count++)) || true
}

# Redirect output if file specified
if [[ -n "$OUTPUT_FILE" ]]; then
    exec > "$OUTPUT_FILE"
fi

# ============================================================================
# Report Generation
# ============================================================================

if $JSON_OUTPUT; then
    echo "{"
    echo "  \"report_type\": \"Access Audit Report\","
    echo "  \"generated\": \"$(date -Iseconds)\","
    echo "  \"hostname\": \"$(hostname)\","
    echo "  \"period\": {"
    echo "    \"days\": $REPORT_DAYS,"
    echo "    \"start\": \"$START_DATE\","
    echo "    \"end\": \"$END_DATE\""
    echo "  },"
else
    print_header "ACCESS AUDIT REPORT"
    echo "Generated:    $(date)"
    echo "Hostname:     $(hostname)"
    echo "Report Period: $START_DATE to $END_DATE ($REPORT_DAYS days)"
    echo "Prepared by:  Automated compliance script"
fi

# ----------------------------------------------------------------------------
# 1. User Account Inventory
# ----------------------------------------------------------------------------

if ! $JSON_OUTPUT; then
    print_header "1. USER ACCOUNT INVENTORY"
fi

# Get users with login shells
declare -a login_users=()
declare -a system_users=()
declare -a locked_users=()

while IFS=: read -r username _ uid _ _ home shell; do
    # Skip if no valid shell
    [[ "$shell" == */nologin ]] || [[ "$shell" == */false ]] && continue

    if [[ $uid -ge 1000 ]] && [[ $uid -lt 65534 ]]; then
        # Check if account is locked
        if passwd -S "$username" 2>/dev/null | grep -q " L "; then
            locked_users+=("$username")
        else
            login_users+=("$username|$uid|$home|$shell")
        fi
    elif [[ $uid -eq 0 ]]; then
        login_users+=("$username|$uid|$home|$shell")
    fi
done < /etc/passwd

if $JSON_OUTPUT; then
    echo "  \"users\": {"
    echo "    \"login_enabled\": ["
    first=true
    for entry in "${login_users[@]:-}"; do
        IFS='|' read -r user uid home shell <<< "$entry"
        $first || echo ","
        first=false
        printf '      {"username": "%s", "uid": %s, "home": "%s", "shell": "%s"}' "$user" "$uid" "$home" "$shell"
    done
    echo ""
    echo "    ],"
    echo "    \"locked\": [$(if [[ ${#locked_users[@]} -gt 0 ]]; then printf '"%s",' "${locked_users[@]}" | sed 's/,$//'; fi)],"
    echo "    \"total_login_accounts\": ${#login_users[@]}"
    echo "  },"
else
    echo ""
    echo "Accounts with login access:"
    printf "  %-15s %-6s %-25s %s\n" "USERNAME" "UID" "HOME" "SHELL"
    print_divider 65
    for entry in "${login_users[@]:-}"; do
        IFS='|' read -r user uid home shell <<< "$entry"
        printf "  %-15s %-6s %-25s %s\n" "$user" "$uid" "$home" "$shell"
    done

    echo ""
    echo "Total login-enabled accounts: ${#login_users[@]}"

    if [[ ${#locked_users[@]} -gt 0 ]]; then
        echo "Locked accounts: ${locked_users[*]}"
    fi

    # Check for accounts without passwords or with weak settings
    if [[ ${#login_users[@]} -gt 5 ]]; then
        add_finding "INFO" "More than 5 user accounts with login access"
    fi
fi

# ----------------------------------------------------------------------------
# 2. SSH Key Inventory
# ----------------------------------------------------------------------------

if ! $JSON_OUTPUT; then
    print_header "2. SSH KEY INVENTORY"
fi

declare -a ssh_keys=()

for entry in "${login_users[@]:-}"; do
    IFS='|' read -r user _ home _ <<< "$entry"
    auth_keys="$home/.ssh/authorized_keys"

    if [[ -f "$auth_keys" ]] && [[ -r "$auth_keys" ]]; then
        key_count=$(grep -c "^ssh-" "$auth_keys" 2>/dev/null || echo "0")
        if [[ $key_count -gt 0 ]]; then
            # Get key fingerprints if possible
            while IFS= read -r key; do
                [[ "$key" =~ ^ssh- ]] || continue
                key_type=$(echo "$key" | awk '{print $1}')
                key_comment=$(echo "$key" | awk '{print $NF}')
                ssh_keys+=("$user|$key_type|$key_comment")
            done < "$auth_keys"
        fi
    fi
done

if $JSON_OUTPUT; then
    echo "  \"ssh_keys\": ["
    first=true
    for entry in "${ssh_keys[@]:-}"; do
        IFS='|' read -r user key_type comment <<< "$entry"
        $first || echo ","
        first=false
        printf '    {"user": "%s", "key_type": "%s", "comment": "%s"}' "$user" "$key_type" "$comment"
    done
    echo ""
    echo "  ],"
else
    if [[ ${#ssh_keys[@]} -gt 0 ]]; then
        printf "  %-15s %-15s %s\n" "USER" "KEY TYPE" "COMMENT/IDENTIFIER"
        print_divider 60
        for entry in "${ssh_keys[@]}"; do
            IFS='|' read -r user key_type comment <<< "$entry"
            printf "  %-15s %-15s %s\n" "$user" "$key_type" "${comment:0:40}"
        done
        echo ""
        echo "Total SSH keys: ${#ssh_keys[@]}"
    else
        echo "No SSH authorized_keys found (or not readable)"
    fi
fi

# ----------------------------------------------------------------------------
# 3. Login Activity Summary
# ----------------------------------------------------------------------------

if ! $JSON_OUTPUT; then
    print_header "3. LOGIN ACTIVITY SUMMARY"
fi

# Get login statistics
declare -A login_counts=()
declare -A login_ips=()
total_logins=0

while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^reboot ]] && continue
    [[ "$line" =~ ^wtmp ]] && continue

    user=$(echo "$line" | awk '{print $1}')
    ip=$(echo "$line" | awk '{print $3}')

    ((login_counts[$user]++)) || true
    login_ips[$user]="${login_ips[$user]:-} $ip"
    ((total_logins++)) || true
done < <(last -s "$START_DATE" 2>/dev/null || last -${REPORT_DAYS}d 2>/dev/null || last | head -100)

if $JSON_OUTPUT; then
    echo "  \"login_activity\": {"
    echo "    \"total_logins\": $total_logins,"
    echo "    \"by_user\": {"
    first=true
    for user in "${!login_counts[@]}"; do
        $first || echo ","
        first=false
        unique_ips=$(echo "${login_ips[$user]}" | tr ' ' '\n' | sort -u | grep -v '^$' | wc -l)
        printf '      "%s": {"count": %d, "unique_ips": %d}' "$user" "${login_counts[$user]}" "$unique_ips"
    done
    echo ""
    echo "    }"
    echo "  },"
else
    echo ""
    echo "Login counts by user (last $REPORT_DAYS days):"
    printf "  %-15s %10s %12s\n" "USER" "LOGINS" "UNIQUE IPs"
    print_divider 40
    for user in "${!login_counts[@]}"; do
        unique_ips=$(echo "${login_ips[$user]}" | tr ' ' '\n' | sort -u | grep -v '^$' | wc -l)
        printf "  %-15s %10d %12d\n" "$user" "${login_counts[$user]}" "$unique_ips"
    done
    echo ""
    echo "Total login sessions: $total_logins"
fi

# ----------------------------------------------------------------------------
# 4. Failed Authentication Attempts
# ----------------------------------------------------------------------------

if ! $JSON_OUTPUT; then
    print_header "4. FAILED AUTHENTICATION ATTEMPTS"
fi

# Count failed attempts from secure log
failed_attempts=0
declare -A failed_by_ip=()
declare -A failed_by_user=()

if [[ -r /var/log/secure ]]; then
    while IFS= read -r line; do
        # Check if line is within date range (simplified check)
        if echo "$line" | grep -q "Failed password\|authentication failure"; then
            ((failed_attempts++)) || true

            ip=$(echo "$line" | grep -oP 'from \K[0-9.]+' || echo "unknown")
            user=$(echo "$line" | grep -oP 'for (invalid user )?\K\w+' || echo "unknown")

            ((failed_by_ip[$ip]++)) || true
            ((failed_by_user[$user]++)) || true
        fi
    done < <(grep -E "Failed password|authentication failure" /var/log/secure 2>/dev/null | tail -1000)
fi

if $JSON_OUTPUT; then
    echo "  \"failed_auth\": {"
    echo "    \"total_attempts\": $failed_attempts,"
    echo "    \"by_ip\": {"
    first=true
    for ip in "${!failed_by_ip[@]}"; do
        $first || echo ","
        first=false
        printf '      "%s": %d' "$ip" "${failed_by_ip[$ip]}"
    done
    echo ""
    echo "    },"
    echo "    \"by_user\": {"
    first=true
    for user in "${!failed_by_user[@]}"; do
        $first || echo ","
        first=false
        printf '      "%s": %d' "$user" "${failed_by_user[$user]}"
    done
    echo ""
    echo "    }"
    echo "  },"
else
    echo ""
    echo "Total failed attempts: $failed_attempts"

    if [[ ${#failed_by_ip[@]} -gt 0 ]]; then
        echo ""
        echo "Failed attempts by source IP (top 10):"
        for ip in "${!failed_by_ip[@]}"; do
            echo "$ip ${failed_by_ip[$ip]}"
        done | sort -k2 -rn | head -10 | while read -r ip count; do
            printf "  %-20s %d attempts\n" "$ip" "$count"
        done
    fi

    if [[ ${#failed_by_user[@]} -gt 0 ]]; then
        echo ""
        echo "Targeted usernames (top 10):"
        for user in "${!failed_by_user[@]}"; do
            echo "$user ${failed_by_user[$user]}"
        done | sort -k2 -rn | head -10 | while read -r user count; do
            printf "  %-20s %d attempts\n" "$user" "$count"
        done
    fi

    if [[ $failed_attempts -gt 100 ]]; then
        add_finding "WARN" "$failed_attempts failed authentication attempts detected"
    fi
fi

# ----------------------------------------------------------------------------
# 5. Sudo/Privilege Escalation Events
# ----------------------------------------------------------------------------

if ! $JSON_OUTPUT; then
    print_header "5. SUDO / PRIVILEGE ESCALATION"
fi

# Get sudo usage from logs
declare -A sudo_by_user=()
declare -a sudo_commands=()
sudo_count=0

if [[ -r /var/log/secure ]]; then
    while IFS= read -r line; do
        if echo "$line" | grep -q "sudo:.*COMMAND="; then
            ((sudo_count++)) || true
            user=$(echo "$line" | grep -oP 'sudo:\s+\K\w+' || echo "unknown")
            cmd=$(echo "$line" | grep -oP 'COMMAND=\K.*' || echo "")
            ((sudo_by_user[$user]++)) || true

            if $FULL_REPORT; then
                sudo_commands+=("$user: $cmd")
            fi
        fi
    done < <(grep "sudo:" /var/log/secure 2>/dev/null | tail -500)
fi

if $JSON_OUTPUT; then
    echo "  \"sudo_activity\": {"
    echo "    \"total_commands\": $sudo_count,"
    echo "    \"by_user\": {"
    first=true
    for user in "${!sudo_by_user[@]}"; do
        $first || echo ","
        first=false
        printf '      "%s": %d' "$user" "${sudo_by_user[$user]}"
    done
    echo ""
    echo "    }"
    echo "  },"
else
    echo ""
    echo "Total sudo commands executed: $sudo_count"

    if [[ ${#sudo_by_user[@]} -gt 0 ]]; then
        echo ""
        echo "Sudo usage by user:"
        for user in "${!sudo_by_user[@]}"; do
            printf "  %-15s %d commands\n" "$user" "${sudo_by_user[$user]}"
        done
    fi

    if $FULL_REPORT && [[ ${#sudo_commands[@]} -gt 0 ]]; then
        echo ""
        echo "Recent sudo commands (last 20):"
        printf '%s\n' "${sudo_commands[@]}" | tail -20 | while read -r cmd; do
            echo "  $cmd"
        done
    fi
fi

# ----------------------------------------------------------------------------
# 6. Sudoers Configuration
# ----------------------------------------------------------------------------

if ! $JSON_OUTPUT; then
    print_header "6. SUDOERS CONFIGURATION"
fi

# Check sudoers file
sudoers_users=()
if [[ -r /etc/sudoers ]]; then
    while IFS= read -r line; do
        # Skip comments and empty lines
        [[ "$line" =~ ^#.*$ ]] && continue
        [[ -z "${line// /}" ]] && continue
        [[ "$line" =~ ^Defaults ]] && continue

        # Look for user/group permissions
        if [[ "$line" =~ ^[a-zA-Z%] ]]; then
            sudoers_users+=("$line")
        fi
    done < /etc/sudoers
fi

# Check sudoers.d
if [[ -d /etc/sudoers.d ]]; then
    for file in /etc/sudoers.d/*; do
        [[ -f "$file" ]] || continue
        [[ -r "$file" ]] || continue
        while IFS= read -r line; do
            [[ "$line" =~ ^#.*$ ]] && continue
            [[ -z "${line// /}" ]] && continue
            [[ "$line" =~ ^Defaults ]] && continue
            if [[ "$line" =~ ^[a-zA-Z%] ]]; then
                sudoers_users+=("$(basename "$file"): $line")
            fi
        done < "$file"
    done
fi

if $JSON_OUTPUT; then
    echo "  \"sudoers\": ["
    first=true
    for entry in "${sudoers_users[@]:-}"; do
        $first || echo ","
        first=false
        printf '    "%s"' "$(echo "$entry" | sed 's/"/\\"/g')"
    done
    echo ""
    echo "  ],"
else
    if [[ ${#sudoers_users[@]} -gt 0 ]]; then
        echo "Sudoers entries:"
        for entry in "${sudoers_users[@]}"; do
            echo "  $entry"
        done
    else
        echo "Could not read sudoers configuration (may need sudo)"
    fi
fi

# ----------------------------------------------------------------------------
# 7. Audit Log Summary (if auditd available)
# ----------------------------------------------------------------------------

if command -v aureport &>/dev/null; then
    if ! $JSON_OUTPUT; then
        print_header "7. AUDIT LOG SUMMARY"
    fi

    # Try to get audit summary
    audit_summary=$(sudo aureport --summary 2>/dev/null || echo "")

    if [[ -n "$audit_summary" ]] && ! $JSON_OUTPUT; then
        echo "$audit_summary" | head -30
    elif ! $JSON_OUTPUT; then
        echo "Audit logs not accessible (may need sudo)"
    fi

    if $JSON_OUTPUT; then
        echo "  \"audit_available\": true,"
    fi
else
    if $JSON_OUTPUT; then
        echo "  \"audit_available\": false,"
    fi
fi

# ----------------------------------------------------------------------------
# 8. System Service Accounts
# ----------------------------------------------------------------------------

if ! $JSON_OUTPUT; then
    print_header "8. SYSTEM SERVICE ACCOUNTS"
fi

# List service accounts (UID < 1000, excluding nobody/nfsnobody)
service_accounts=()
while IFS=: read -r username _ uid _ comment home shell; do
    [[ $uid -ge 1000 ]] && continue
    [[ $uid -eq 65534 ]] && continue
    [[ "$shell" == */nologin ]] && continue
    [[ "$shell" == */false ]] && continue
    service_accounts+=("$username|$uid|$shell|$comment")
done < /etc/passwd

if $JSON_OUTPUT; then
    echo "  \"service_accounts\": ["
    first=true
    for entry in "${service_accounts[@]:-}"; do
        IFS='|' read -r user uid shell comment <<< "$entry"
        $first || echo ","
        first=false
        printf '    {"username": "%s", "uid": %s, "shell": "%s"}' "$user" "$uid" "$shell"
    done
    echo ""
    echo "  ],"
else
    echo "Service accounts with login shells:"
    if [[ ${#service_accounts[@]} -gt 0 ]]; then
        printf "  %-15s %-6s %-20s %s\n" "USERNAME" "UID" "SHELL" "DESCRIPTION"
        print_divider 60
        for entry in "${service_accounts[@]}"; do
            IFS='|' read -r user uid shell comment <<< "$entry"
            printf "  %-15s %-6s %-20s %s\n" "$user" "$uid" "$shell" "${comment:0:20}"
        done
    else
        echo "  No service accounts with login shells (good)"
    fi

    if [[ ${#service_accounts[@]} -gt 2 ]]; then
        add_finding "INFO" "${#service_accounts[@]} service accounts have login shells"
    fi
fi

# ----------------------------------------------------------------------------
# 9. Security Configuration Posture
# ----------------------------------------------------------------------------

if ! $JSON_OUTPUT; then
    print_header "9. SECURITY CONFIGURATION POSTURE"
fi

# Check SELinux
selinux_status="disabled"
selinux_mode="N/A"
if command -v getenforce &>/dev/null; then
    selinux_status="enabled"
    selinux_mode=$(getenforce 2>/dev/null || echo "unknown")
fi

# Check firewall
firewall_status="inactive"
firewall_type="none"
if systemctl is-active --quiet firewalld 2>/dev/null; then
    firewall_status="active"
    firewall_type="firewalld"
elif systemctl is-active --quiet iptables 2>/dev/null; then
    firewall_status="active"
    firewall_type="iptables"
elif systemctl is-active --quiet ufw 2>/dev/null; then
    firewall_status="active"
    firewall_type="ufw"
fi

# Check key kernel security parameters
declare -A sysctl_checks=(
    ["net.ipv4.conf.all.rp_filter"]="1 or 2"
    ["net.ipv4.conf.all.accept_redirects"]="0"
    ["net.ipv4.conf.all.send_redirects"]="0"
    ["net.ipv4.tcp_syncookies"]="1"
    ["net.ipv4.icmp_echo_ignore_broadcasts"]="1"
)

declare -A sysctl_values=()
declare -a sysctl_issues=()

for param in "${!sysctl_checks[@]}"; do
    value=$(sysctl -n "$param" 2>/dev/null || echo "N/A")
    sysctl_values["$param"]="$value"
    expected="${sysctl_checks[$param]}"

    # Check if value meets expectation
    case "$param" in
        *rp_filter)
            if [[ "$value" != "1" ]] && [[ "$value" != "2" ]]; then
                sysctl_issues+=("$param=$value (expected: $expected)")
            fi
            ;;
        *)
            if [[ "$value" != "${expected}" ]]; then
                sysctl_issues+=("$param=$value (expected: $expected)")
            fi
            ;;
    esac
done

# Check SSH configuration
ssh_root_login="unknown"
ssh_password_auth="unknown"
if [[ -r /etc/ssh/sshd_config ]]; then
    ssh_root_login=$(grep -E "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "default")
    ssh_password_auth=$(grep -E "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "default")
fi

if $JSON_OUTPUT; then
    echo "  \"security_posture\": {"
    echo "    \"selinux\": {"
    echo "      \"status\": \"$selinux_status\","
    echo "      \"mode\": \"$selinux_mode\""
    echo "    },"
    echo "    \"firewall\": {"
    echo "      \"status\": \"$firewall_status\","
    echo "      \"type\": \"$firewall_type\""
    echo "    },"
    echo "    \"kernel_hardening\": {"
    first=true
    for param in "${!sysctl_values[@]}"; do
        $first || echo ","
        first=false
        printf '      "%s": "%s"' "$param" "${sysctl_values[$param]}"
    done
    echo ""
    echo "    },"
    echo "    \"ssh\": {"
    echo "      \"permit_root_login\": \"${ssh_root_login:-default}\","
    echo "      \"password_auth\": \"${ssh_password_auth:-default}\""
    echo "    },"
    echo "    \"issues\": [$(if [[ ${#sysctl_issues[@]} -gt 0 ]]; then printf '"%s",' "${sysctl_issues[@]}" | sed 's/,$//'; fi)]"
    echo "  },"
else
    echo ""
    echo "SELinux:"
    echo "  Status: $selinux_status"
    echo "  Mode:   $selinux_mode"
    if [[ "$selinux_mode" != "Enforcing" ]] && [[ "$selinux_status" == "enabled" ]]; then
        add_finding "WARN" "SELinux is not in Enforcing mode (current: $selinux_mode)"
    fi

    echo ""
    echo "Firewall:"
    echo "  Status: $firewall_status"
    echo "  Type:   $firewall_type"
    if [[ "$firewall_status" != "active" ]]; then
        add_finding "CRITICAL" "No active firewall detected"
    fi

    echo ""
    echo "Kernel Security Parameters:"
    printf "  %-45s %s\n" "PARAMETER" "VALUE"
    print_divider 55
    for param in "${!sysctl_values[@]}"; do
        printf "  %-45s %s\n" "$param" "${sysctl_values[$param]}"
    done

    if [[ ${#sysctl_issues[@]} -gt 0 ]]; then
        echo ""
        echo "  Issues detected:"
        for issue in "${sysctl_issues[@]}"; do
            echo "    - $issue"
            add_finding "WARN" "Kernel parameter: $issue"
        done
    fi

    echo ""
    echo "SSH Configuration:"
    echo "  PermitRootLogin:      ${ssh_root_login:-default}"
    echo "  PasswordAuthentication: ${ssh_password_auth:-default}"
    if [[ "$ssh_root_login" == "yes" ]]; then
        add_finding "WARN" "SSH root login is permitted"
    fi
fi

# ----------------------------------------------------------------------------
# 10. Findings Summary
# ----------------------------------------------------------------------------

exit_code=0
if [[ ${#findings[@]} -gt 0 ]]; then
    exit_code=2
fi

if $JSON_OUTPUT; then
    echo "  \"findings\": ["
    first=true
    for finding in "${findings[@]:-}"; do
        $first || echo ","
        first=false
        printf '    "%s"' "$(echo "$finding" | sed 's/"/\\"/g')"
    done
    echo ""
    echo "  ],"
    echo "  \"findings_count\": $findings_count"
    echo "}"
else
    print_header "FINDINGS SUMMARY"
    if [[ ${#findings[@]} -gt 0 ]]; then
        echo "The following items may require attention:"
        echo ""
        for finding in "${findings[@]}"; do
            echo "  $finding"
        done
    else
        echo "No significant findings."
    fi

    print_header "REPORT COMPLETE"
    echo "Generated: $(date)"
    echo "Total findings: $findings_count"

    if [[ -n "$OUTPUT_FILE" ]]; then
        echo ""
        echo "Report saved to: $OUTPUT_FILE"
    fi
fi

exit $exit_code
