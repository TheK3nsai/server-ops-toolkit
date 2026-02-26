# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Related Repository

This repo works alongside `/home/kensai/docker` — the Docker infrastructure repository containing all compose stacks, Traefik config, monitoring, and service definitions. Both repos are managed collaboratively by Claude Code and should be cross-referenced when making changes:

- **This repo (ops)**: Monitoring scripts, cron jobs, security auditing, system maintenance, config backups
- **Docker repo** (`/home/kensai/docker`): Compose stacks, Traefik routing, Grafana alerting, service configuration

When modifying scripts that interact with Docker (health checks, resource reports, backups, cleanup), consult the Docker repo's `CLAUDE.md` for current container inventory, network topology, and service architecture. When adding services in the Docker repo, update the ops backup patterns and monitoring if needed.

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
- `MEM_WARN_THRESHOLD`, `MEM_CRIT_THRESHOLD`, `SWAP_WARN_THRESHOLD` - Memory alert thresholds
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
| memory-swap-monitor.sh | Monitor memory/swap usage with OOM detection | No |
| system-updates.sh | Check for available dnf/yum updates | No |
| backup-configs.sh | Backup system and Docker configs | Partial |
| login-history.sh | Report user login/logout history | Yes |
| access-audit-report.sh | Compliance-focused access audit | Yes |

## Configuration Files

- `conf/allowed-ports.conf` - Whitelist of expected open ports (used by open-ports-audit.sh)
- `conf/fail2ban-local.conf` - Fail2ban jail configuration template (copy to /etc/fail2ban/jail.d/)
- `conf/logwatch.conf` - Logwatch configuration template
- `/etc/docker/daemon.json` - Docker log rotation (json-file, 10m max, 3 files)

## System Services

- `dnf-automatic-install.timer` - Security-only auto-updates (via dnf-automatic), fires at 6:00 AM with up to 60 min random delay

## Cron Scheduling

**dnf-automatic conflict**: The `dnf-automatic-install.timer` runs between 6:00–7:00 AM and holds the dnf lock. Any cron job that calls `dnf` (e.g., `system-updates.sh`) must be scheduled **after 7:00 AM** to avoid hanging on the lock. Current schedule uses 8:00 AM.

Templates in `cron.d/` should stay in sync with the live crontab. After editing either, update the other.

## Cron Job Installation

Templates in `cron.d/` are for user crontabs. To install:

```bash
# View and selectively copy to your crontab
cat cron.d/security-checks.cron
crontab -e

# Or install all (review first!)
cat cron.d/*.cron >> /tmp/ops-cron && crontab /tmp/ops-cron
```

## Known Gotchas

### Rocky Linux 10 Specifics
- **No `bc` installed** — all arithmetic must use pure bash (`$(( ))`, `${var%.*}`). Do not introduce `bc` or `awk` math dependencies.
- **`needs-restarting` is a dnf subcommand, not a standalone binary** — use `dnf needs-restarting -r` (exit 0 = no reboot, exit 1 = reboot needed). Do not rely on `command -v needs-restarting`.
- **Rocky mirrorlist outages** — `mirrors.rockylinux.org` can go down. Repos may be pointed at `mirror.netzwerge.de` as a workaround. See the Docker repo's CLAUDE.md for restore/re-apply instructions.

### Docker Integration
- **One-shot containers** (e.g., `zammad-init`) exit with code 0 after initialization and are not restarted. The health check script recognizes these by checking `exit_code == 0` combined with `restart_policy` of `no` or `on-failure`. Don't flag them as failures.
- **`DOCKER_ROOT`** in `conf/.env` points to `/home/kensai/docker` (the compose project directory), not Docker's data root (`/var/lib/docker`).
- **backup-configs.sh** backs up Docker stack configs using glob patterns in `DOCKER_CONFIGS`. When adding new stacks with non-standard config file types, add matching patterns to the array.

### Cron Jobs
- **`--quiet` flag** on scripts means output only on errors/threshold breaches. A 0-byte log is normal when everything is healthy.
- **Log rotation** is handled by a cron `find/truncate` (Sundays at midnight), not logrotate. Logs over 10MB are truncated to zero.
- **Crontab vs cron.d/ templates**: The live crontab is the source of truth. Templates in `cron.d/` are reference copies — keep them in sync after schedule changes.
