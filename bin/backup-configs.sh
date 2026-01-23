#!/usr/bin/env bash
# backup-configs.sh - Backup system and Docker configuration files
#
# Purpose: Create timestamped backups of important system configs,
#          Docker compose files, and application configs
#
# Usage: ./backup-configs.sh [--dest PATH] [--compress] [--list] [--restore FILE]
#        --dest PATH    : Backup destination (default: /home/kensai/ops/backups)
#        --compress     : Create compressed tarball
#        --list         : List available backups
#        --restore FILE : Restore from backup file
#        --dry-run      : Show what would be backed up
#
# Dependencies: tar, gzip (optional)
#
# Exit codes: 0=success, 1=error

set -euo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../lib/common.sh"

# Configuration
BACKUP_DEST="${BACKUP_DEST:-/home/kensai/ops/backups}"
DOCKER_ROOT="${DOCKER_ROOT:-/home/kensai/docker}"
OPS_ROOT="${OPS_ROOT:-/home/kensai/ops}"
COMPRESS=false
LIST_BACKUPS=false
RESTORE_FILE=""
DRY_RUN=false
RETENTION_DAYS="${BACKUP_RETENTION_DAYS:-30}"

# Files and directories to backup
SYSTEM_CONFIGS=(
    "/etc/ssh/sshd_config"
    "/etc/fail2ban"
    "/etc/firewalld"
    "/etc/sysctl.conf"
    "/etc/sysctl.d"
    "/etc/security/limits.conf"
    "/etc/security/limits.d"
    "/etc/chrony.conf"
    "/etc/logrotate.conf"
    "/etc/logrotate.d"
    "/etc/crontab"
    "/etc/cron.d"
    "/var/spool/cron"
    "/etc/systemd/system/*.service"
    "/etc/systemd/system/*.timer"
    "/etc/docker/daemon.json"
    "/etc/hosts"
    "/etc/hostname"
    "/etc/resolv.conf"
)

# Docker-related paths (compose files and .env, not volumes)
DOCKER_CONFIGS=(
    "docker-compose.yml"
    "docker-compose.yaml"
    "compose.yml"
    "compose.yaml"
    ".env"
    "*.conf"
    "config/"
    "traefik/"
)

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dest)
            BACKUP_DEST="$2"
            shift 2
            ;;
        --compress)
            COMPRESS=true
            shift
            ;;
        --list)
            LIST_BACKUPS=true
            shift
            ;;
        --restore)
            RESTORE_FILE="$2"
            shift 2
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [--dest PATH] [--compress] [--list] [--restore FILE] [--dry-run]"
            echo ""
            echo "Options:"
            echo "  --dest PATH    : Backup destination (default: $BACKUP_DEST)"
            echo "  --compress     : Create compressed tarball"
            echo "  --list         : List available backups"
            echo "  --restore FILE : Restore from backup file"
            echo "  --dry-run      : Show what would be backed up"
            echo ""
            echo "Environment variables:"
            echo "  BACKUP_DEST         : Backup destination directory"
            echo "  BACKUP_RETENTION_DAYS: Days to keep backups (default: 30)"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# List backups
if $LIST_BACKUPS; then
    print_header "Available Backups"
    echo "Location: $BACKUP_DEST"
    echo ""

    if [[ -d "$BACKUP_DEST" ]]; then
        # Find and list backups with size and date
        find "$BACKUP_DEST" -maxdepth 1 -name "config-backup-*" -type d -o -name "config-backup-*.tar.gz" -type f 2>/dev/null | \
            while read -r backup; do
                if [[ -d "$backup" ]]; then
                    size=$(du -sh "$backup" 2>/dev/null | awk '{print $1}')
                    date=$(stat -c %y "$backup" 2>/dev/null | cut -d' ' -f1)
                    printf "%-50s %8s  %s\n" "$(basename "$backup")/" "$size" "$date"
                else
                    size=$(ls -lh "$backup" 2>/dev/null | awk '{print $5}')
                    date=$(stat -c %y "$backup" 2>/dev/null | cut -d' ' -f1)
                    printf "%-50s %8s  %s\n" "$(basename "$backup")" "$size" "$date"
                fi
            done | sort -r

        echo ""
        total_size=$(du -sh "$BACKUP_DEST" 2>/dev/null | awk '{print $1}')
        echo "Total backup size: $total_size"
    else
        echo "No backups found"
    fi
    exit 0
fi

# Restore from backup
if [[ -n "$RESTORE_FILE" ]]; then
    if [[ ! -e "$RESTORE_FILE" ]]; then
        log_error "Backup not found: $RESTORE_FILE"
        exit 1
    fi

    print_header "Restore from Backup"
    echo "Source: $RESTORE_FILE"
    echo ""
    log_warn "This will show restore instructions only."
    log_warn "Manual restore is recommended to avoid overwriting current configs."
    echo ""

    if [[ "$RESTORE_FILE" == *.tar.gz ]]; then
        echo "Contents of backup:"
        tar -tzf "$RESTORE_FILE" | head -30
        echo "..."
        echo ""
        echo "To extract:"
        echo "  mkdir -p /tmp/restore"
        echo "  tar -xzf $RESTORE_FILE -C /tmp/restore"
        echo "  # Then manually copy needed files"
    elif [[ -d "$RESTORE_FILE" ]]; then
        echo "Contents of backup:"
        find "$RESTORE_FILE" -type f | head -30
        echo ""
        echo "To restore system configs (requires sudo):"
        echo "  sudo cp -r $RESTORE_FILE/system/* /"
        echo ""
        echo "To restore Docker configs:"
        echo "  cp -r $RESTORE_FILE/docker/* $DOCKER_ROOT/"
    fi
    exit 0
fi

# Create backup
TIMESTAMP=$(date '+%Y%m%d-%H%M%S')
BACKUP_NAME="config-backup-${TIMESTAMP}"
BACKUP_PATH="${BACKUP_DEST}/${BACKUP_NAME}"

print_header "Configuration Backup"
echo "Timestamp: $TIMESTAMP"
echo "Destination: $BACKUP_PATH"
$DRY_RUN && echo "MODE: DRY RUN"

# Create backup directories
if ! $DRY_RUN; then
    mkdir -p "${BACKUP_PATH}/system"
    mkdir -p "${BACKUP_PATH}/docker"
    mkdir -p "${BACKUP_PATH}/ops"
fi

# Backup system configs
print_header "System Configuration Files"
backed_up=0
skipped=0

for config in "${SYSTEM_CONFIGS[@]}"; do
    # Handle glob patterns
    if [[ "$config" == *"*"* ]]; then
        # Expand glob
        for expanded in $config; do
            if [[ -e "$expanded" ]]; then
                rel_path="${expanded#/}"
                dest_dir="${BACKUP_PATH}/system/$(dirname "$rel_path")"

                if $DRY_RUN; then
                    echo "  [WOULD BACKUP] $expanded"
                else
                    mkdir -p "$dest_dir"
                    if cp -a "$expanded" "$dest_dir/" 2>/dev/null; then
                        echo "  [OK] $expanded"
                        ((backed_up++)) || true
                    else
                        echo "  [SKIP] $expanded (permission denied)"
                        ((skipped++)) || true
                    fi
                fi
            fi
        done
    elif [[ -e "$config" ]]; then
        rel_path="${config#/}"
        dest_dir="${BACKUP_PATH}/system/$(dirname "$rel_path")"

        if $DRY_RUN; then
            echo "  [WOULD BACKUP] $config"
        else
            mkdir -p "$dest_dir"
            if cp -a "$config" "$dest_dir/" 2>/dev/null; then
                echo "  [OK] $config"
                ((backed_up++)) || true
            else
                echo "  [SKIP] $config (permission denied or error)"
                ((skipped++)) || true
            fi
        fi
    else
        echo "  [SKIP] $config (not found)"
        ((skipped++)) || true
    fi
done

# Backup Docker configurations
print_header "Docker Stack Configurations"

if [[ -d "$DOCKER_ROOT" ]]; then
    # Find all compose project directories
    for stack_dir in "$DOCKER_ROOT"/*/; do
        [[ ! -d "$stack_dir" ]] && continue
        stack_name=$(basename "$stack_dir")

        # Skip hidden directories and non-stack dirs
        [[ "$stack_name" == .* ]] && continue

        stack_backed_up=false

        for pattern in "${DOCKER_CONFIGS[@]}"; do
            for file in "$stack_dir"$pattern; do
                if [[ -e "$file" ]]; then
                    rel_path="${file#$DOCKER_ROOT/}"
                    dest_dir="${BACKUP_PATH}/docker/$(dirname "$rel_path")"

                    if $DRY_RUN; then
                        echo "  [WOULD BACKUP] $file"
                    else
                        mkdir -p "$dest_dir"
                        if cp -a "$file" "$dest_dir/" 2>/dev/null; then
                            stack_backed_up=true
                            ((backed_up++)) || true
                        fi
                    fi
                fi
            done
        done

        if $stack_backed_up || $DRY_RUN; then
            echo "  [OK] Stack: $stack_name"
        fi
    done

    # Backup root-level docker files
    for pattern in "${DOCKER_CONFIGS[@]}"; do
        for file in "$DOCKER_ROOT"/$pattern; do
            if [[ -e "$file" ]] && [[ -f "$file" ]]; then
                if $DRY_RUN; then
                    echo "  [WOULD BACKUP] $file"
                else
                    cp -a "$file" "${BACKUP_PATH}/docker/" 2>/dev/null && ((backed_up++)) || true
                fi
            fi
        done
    done
else
    echo "  Docker root not found: $DOCKER_ROOT"
fi

# Backup ops configs
print_header "Ops Configuration"

if [[ -d "$OPS_ROOT/conf" ]]; then
    if $DRY_RUN; then
        echo "  [WOULD BACKUP] $OPS_ROOT/conf/"
    else
        cp -a "$OPS_ROOT/conf" "${BACKUP_PATH}/ops/" 2>/dev/null && echo "  [OK] ops/conf/"
        ((backed_up++)) || true
    fi
fi

# Create manifest
if ! $DRY_RUN; then
    {
        echo "# Backup Manifest"
        echo "# Created: $(date)"
        echo "# Hostname: $(hostname)"
        echo "# OS: $(cat /etc/redhat-release 2>/dev/null || echo 'Unknown')"
        echo ""
        echo "## Files backed up:"
        find "${BACKUP_PATH}" -type f | sed "s|${BACKUP_PATH}/||"
    } > "${BACKUP_PATH}/MANIFEST.txt"
fi

# Compress if requested
if $COMPRESS && ! $DRY_RUN; then
    print_header "Compressing Backup"
    tar_file="${BACKUP_DEST}/${BACKUP_NAME}.tar.gz"

    if tar -czf "$tar_file" -C "$BACKUP_DEST" "$BACKUP_NAME"; then
        rm -rf "$BACKUP_PATH"
        BACKUP_PATH="$tar_file"
        log_success "Created: $tar_file"
    else
        log_error "Compression failed"
    fi
fi

# Cleanup old backups
if ! $DRY_RUN && [[ -d "$BACKUP_DEST" ]]; then
    print_header "Cleanup Old Backups"
    echo "Retention: $RETENTION_DAYS days"

    old_backups=$(find "$BACKUP_DEST" -maxdepth 1 \( -name "config-backup-*" -type d -o -name "config-backup-*.tar.gz" -type f \) -mtime +${RETENTION_DAYS} 2>/dev/null)

    if [[ -n "$old_backups" ]]; then
        echo "$old_backups" | while read -r old; do
            log_info "Removing old backup: $(basename "$old")"
            rm -rf "$old"
        done
    else
        echo "No backups older than $RETENTION_DAYS days"
    fi
fi

# Summary
print_header "Backup Summary"
if $DRY_RUN; then
    echo "DRY RUN - no files were backed up"
else
    if [[ -d "$BACKUP_PATH" ]]; then
        backup_size=$(du -sh "$BACKUP_PATH" 2>/dev/null | awk '{print $1}')
    else
        backup_size=$(ls -lh "$BACKUP_PATH" 2>/dev/null | awk '{print $5}')
    fi

    echo "Backup location: $BACKUP_PATH"
    echo "Files backed up: $backed_up"
    echo "Files skipped:   $skipped"
    echo "Backup size:     ${backup_size:-unknown}"
fi

print_divider

if $DRY_RUN; then
    log_info "Dry run complete"
    echo "Run without --dry-run to create backup"
elif [[ $backed_up -gt 0 ]]; then
    log_success "Backup complete"
else
    log_warn "No files were backed up"
fi

# Note about permissions
if [[ $skipped -gt 0 ]] && [[ $EUID -ne 0 ]]; then
    echo ""
    log_info "Some system files skipped (run with sudo for full backup)"
fi

exit 0
