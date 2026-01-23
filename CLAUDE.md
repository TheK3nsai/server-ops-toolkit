# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

This is an ops toolkit for Linux server administration—a collection of bash scripts for security monitoring, Docker management, system maintenance, and compliance auditing. Target environment is RHEL/Fedora-family systems using systemd, firewalld, and fail2ban.

## Repository Structure

```
bin/           Executable scripts (chmod +x)
conf/          Configuration files and templates
conf/.env      Environment variables (gitignored, contains secrets)
cron.d/        Cron job templates (copy to user crontab or /etc/cron.d)
lib/           Shared libraries (source, don't execute)
logs/          Script output logs (gitignored)
backups/       Config backups (gitignored)
```

## Running Scripts

All scripts support `--help`, `--json` for machine-readable output, and most support `--quiet` for cron usage (only output on errors).

```bash
# Run directly
./bin/docker-health-check.sh --json

# Scripts requiring root access
sudo ./bin/check-auth-logs.sh
sudo ./bin/backup-configs.sh --compress

# Validate script syntax
bash -n ./bin/script-name.sh
```

## Script Development

### Using lib/common.sh

All scripts should source the shared library:

```bash
#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../lib/common.sh"
```

Available functions from common.sh:
- `log_info`, `log_warn`, `log_error`, `log_success` - Timestamped logging
- `setup_logging SCRIPT_NAME` - Redirect output to both console and log file
- `notify_uptime_kuma URL [status] [msg] [ping]` - Push monitoring integration
- `notify_email SUBJECT BODY [recipient]` - Send alert emails
- `require_root` - Exit if not running as root
- `require_command CMD` - Exit if command not available
- `is_service_active SERVICE` - Check systemd service status
- `print_header TITLE` - Formatted section headers
- `human_size BYTES` - Convert bytes to human readable
- `exceeds_threshold VALUE THRESHOLD` - Numeric comparison

### Exit Codes Convention

- 0: Success/clean
- 1: Error (script failure, missing dependency)
- 2: Warning condition (threshold exceeded but not critical)
- 3: Critical condition (immediate attention needed)

### Environment Variables

Scripts read configuration from `conf/.env`. Key variables:
- `DOCKER_ROOT` - Path to Docker compose projects (default: /home/kensai/docker)
- `ALERT_EMAIL` - Default email for notifications
- `DISK_WARN_THRESHOLD`, `DISK_CRIT_THRESHOLD` - Disk usage alert thresholds
- `BACKUP_RETENTION_DAYS` - Days to keep config backups
- `UPTIME_KUMA_*_PUSH` - Push URLs for Uptime Kuma monitoring

## Key Scripts

| Script | Purpose | Requires Root |
|--------|---------|---------------|
| check-auth-logs.sh | Analyze /var/log/secure for suspicious activity | Yes |
| fail2ban-status.sh | Report fail2ban jail status and banned IPs | Yes |
| open-ports-audit.sh | Compare open ports against allowed-ports.conf | Yes |
| docker-health-check.sh | Monitor container health, optional auto-restart | No |
| container-resource-report.sh | CPU/memory usage per container | No |
| docker-cleanup.sh | Prune unused Docker resources | No |
| disk-usage-alert.sh | Check filesystem usage against thresholds | No |
| system-updates.sh | Check for available dnf/yum updates | No |
| backup-configs.sh | Backup system and Docker configs | Partial |
| login-history.sh | Report user login/logout history | Yes |
| access-audit-report.sh | Compliance-focused access audit | Yes |

## Configuration Files

- `conf/allowed-ports.conf` - Whitelist of expected open ports (used by open-ports-audit.sh)
- `conf/fail2ban-local.conf` - Fail2ban jail configuration template (copy to /etc/fail2ban/jail.d/)
- `conf/logwatch.conf` - Logwatch configuration template

## Cron Job Installation

Templates in `cron.d/` are for user crontabs. To install:

```bash
# View and selectively copy to your crontab
cat cron.d/security-checks.cron
crontab -e

# Or install all (review first!)
cat cron.d/*.cron >> /tmp/ops-cron && crontab /tmp/ops-cron
```
