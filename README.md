# Server Ops Toolkit

Bash scripts for Linux server administration, security monitoring, and compliance auditing. Designed for RHEL/Fedora-family systems running Docker infrastructure.

## Features

| Category | Scripts | Description |
|----------|---------|-------------|
| **Security** | `check-auth-logs.sh`, `fail2ban-status.sh`, `open-ports-audit.sh` | Monitor authentication, intrusion prevention, network exposure |
| **Docker** | `docker-health-check.sh`, `container-resource-report.sh`, `docker-cleanup.sh` | Container health, resource usage, cleanup |
| **System** | `disk-usage-alert.sh`, `system-updates.sh`, `backup-configs.sh` | Disk monitoring, updates, configuration backup |
| **Compliance** | `login-history.sh`, `access-audit-report.sh` | User access tracking, audit reports |

## Quick Start

```bash
# Clone the repo
git clone https://github.com/yourusername/server-ops-toolkit.git ~/ops
cd ~/ops

# Copy and configure environment
cp conf/.env.example conf/.env
vim conf/.env

# Run a health check
./bin/docker-health-check.sh

# Run security audit (requires sudo)
sudo ./bin/check-auth-logs.sh
```

## Architecture

```
ops/
├── bin/               # Executable scripts
├── conf/              # Configuration files
│   ├── .env           # Environment variables (secrets)
│   ├── allowed-ports.conf    # Expected open ports whitelist
│   ├── fail2ban-local.conf   # Fail2ban jail template
│   └── logwatch.conf         # Logwatch config template
├── cron.d/            # Cron job templates
├── lib/               # Shared bash library
│   └── common.sh      # Logging, notifications, utilities
├── logs/              # Script output (gitignored)
└── backups/           # Config backups (gitignored)
```

## Script Reference

All scripts support `--help` for usage details and `--json` for machine-readable output.

### Security Monitoring

| Script | Purpose | Cron Suggestion |
|--------|---------|-----------------|
| `check-auth-logs.sh` | Analyze /var/log/secure for failed logins, suspicious sudo | Hourly (quiet), daily (full) |
| `fail2ban-status.sh` | Report jail status, banned IPs, ban history | Every 15 min |
| `open-ports-audit.sh` | Compare open ports against allowed whitelist | Daily |

### Docker Management

| Script | Purpose | Cron Suggestion |
|--------|---------|-----------------|
| `docker-health-check.sh` | Container health status, auto-restart option | Every 5 min |
| `container-resource-report.sh` | CPU/memory usage per container with alerts | Hourly |
| `docker-cleanup.sh` | Prune unused images, containers, volumes | Weekly |

### System Maintenance

| Script | Purpose | Cron Suggestion |
|--------|---------|-----------------|
| `disk-usage-alert.sh` | Filesystem usage with warning/critical thresholds | Every 6 hours |
| `system-updates.sh` | Check for available dnf/yum updates | Daily |
| `backup-configs.sh` | Backup system and Docker configuration files | Daily |

### Compliance & Auditing

| Script | Purpose | Cron Suggestion |
|--------|---------|-----------------|
| `login-history.sh` | User login/logout history with session duration | Daily |
| `access-audit-report.sh` | Comprehensive access audit for compliance | Weekly/Monthly |

## Configuration

### Environment Variables

Create `conf/.env` from the example:

```bash
cp conf/.env.example conf/.env
```

Key variables:
- `DOCKER_ROOT` - Path to Docker compose projects
- `ALERT_EMAIL` - Email for notifications
- `DISK_WARN_THRESHOLD` / `DISK_CRIT_THRESHOLD` - Disk alert thresholds (%)
- `UPTIME_KUMA_*_PUSH` - Push URLs for Uptime Kuma integration

### Allowed Ports

Edit `conf/allowed-ports.conf` to whitelist expected open ports:

```
22/tcp      # SSH
80/tcp      # HTTP
443/tcp     # HTTPS
```

Ports not in this list trigger warnings in `open-ports-audit.sh`.

### Fail2ban

Install the jail configuration:

```bash
sudo cp conf/fail2ban-local.conf /etc/fail2ban/jail.d/local.conf
sudo systemctl restart fail2ban
```

## Cron Setup

Templates in `cron.d/` are ready to install. Review and customize:

```bash
# View available cron templates
ls cron.d/

# Install security monitoring
cat cron.d/security-checks.cron
crontab -e  # paste relevant lines
```

## Shared Library

All scripts source `lib/common.sh` which provides:

- **Logging**: `log_info`, `log_warn`, `log_error`, `log_success`
- **Notifications**: `notify_uptime_kuma`, `notify_email`
- **Utilities**: `require_root`, `require_command`, `is_service_active`
- **Formatting**: `print_header`, `print_divider`, `human_size`

## Integration

### Uptime Kuma

Configure push URLs in `conf/.env`:

```bash
UPTIME_KUMA_AUTH_PUSH="https://uptime.example.com/api/push/xxx"
UPTIME_KUMA_DOCKER_PUSH="https://uptime.example.com/api/push/yyy"
UPTIME_KUMA_DISK_PUSH="https://uptime.example.com/api/push/zzz"
```

Scripts automatically push status on each run.

### Docker Infrastructure

Designed to complement a Docker-based infrastructure. Set `DOCKER_ROOT` to your compose project directory:

```bash
DOCKER_ROOT=/home/user/docker
```

## Requirements

- Bash 4.0+
- RHEL/Fedora/CentOS (uses dnf, firewalld, fail2ban)
- Standard utilities: grep, awk, sort, uniq, bc
- Optional: Docker, jq, mail

## License

MIT
