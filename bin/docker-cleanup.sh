#!/usr/bin/env bash
# docker-cleanup.sh - Clean up unused Docker resources
#
# Purpose: Remove unused images, stopped containers, orphaned volumes,
#          and unused networks to reclaim disk space
#
# Usage: ./docker-cleanup.sh [--dry-run] [--all] [--images] [--volumes] [--force]
#        --dry-run  : Show what would be removed without removing
#        --all      : Remove all unused resources (default)
#        --images   : Only clean unused images
#        --volumes  : Also remove unused volumes (careful!)
#        --force    : Skip confirmation prompts
#        --age DAYS : Only remove images older than DAYS (default: 7)
#
# Dependencies: docker
#
# Exit codes: 0=success, 1=error

set -euo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../lib/common.sh"

# Configuration
DRY_RUN=false
CLEAN_IMAGES=true
CLEAN_CONTAINERS=true
CLEAN_NETWORKS=true
CLEAN_VOLUMES=false  # Dangerous, off by default
CLEAN_BUILD_CACHE=true
FORCE=false
AGE_DAYS=7

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --all)
            CLEAN_IMAGES=true
            CLEAN_CONTAINERS=true
            CLEAN_NETWORKS=true
            CLEAN_BUILD_CACHE=true
            shift
            ;;
        --images)
            CLEAN_CONTAINERS=false
            CLEAN_NETWORKS=false
            CLEAN_BUILD_CACHE=false
            shift
            ;;
        --volumes)
            CLEAN_VOLUMES=true
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --age)
            AGE_DAYS="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--dry-run] [--all] [--images] [--volumes] [--force] [--age DAYS]"
            echo ""
            echo "Options:"
            echo "  --dry-run  : Show what would be removed without removing"
            echo "  --all      : Remove all unused resources (default behavior)"
            echo "  --images   : Only clean unused images"
            echo "  --volumes  : Also remove unused volumes (DANGEROUS - data loss possible)"
            echo "  --force    : Skip confirmation prompts"
            echo "  --age DAYS : Only remove images older than DAYS (default: 7)"
            echo ""
            echo "By default, this script removes:"
            echo "  - Stopped containers"
            echo "  - Unused images (dangling and unreferenced)"
            echo "  - Unused networks"
            echo "  - Build cache"
            echo ""
            echo "Volumes are NOT removed unless --volumes is specified."
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

# Get current disk usage
get_disk_usage() {
    docker system df --format "{{.Type}}|{{.TotalCount}}|{{.Size}}|{{.Reclaimable}}" 2>/dev/null
}

print_header "Docker Cleanup"
echo "Generated: $(date)"
$DRY_RUN && echo "MODE: DRY RUN (no changes will be made)"
echo ""

# Show current state
print_header "Current Docker Disk Usage"
printf "%-15s %10s %12s %15s\n" "TYPE" "COUNT" "SIZE" "RECLAIMABLE"
print_divider 55

while IFS='|' read -r type count size reclaimable; do
    printf "%-15s %10s %12s %15s\n" "$type" "$count" "$size" "$reclaimable"
done < <(get_disk_usage)

# Track what we'll clean
declare -a to_remove_containers=()
declare -a to_remove_images=()
declare -a to_remove_volumes=()
declare -a to_remove_networks=()

# Find stopped containers
if $CLEAN_CONTAINERS; then
    print_header "Stopped Containers"
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        to_remove_containers+=("$line")
        echo "  $line"
    done < <(docker ps -a --filter "status=exited" --filter "status=dead" --filter "status=created" --format "{{.Names}} ({{.Status}})" 2>/dev/null)

    if [[ ${#to_remove_containers[@]} -eq 0 ]]; then
        echo "  None found"
    fi
fi

# Find unused images
if $CLEAN_IMAGES; then
    print_header "Unused Images"

    # Dangling images (untagged)
    echo "Dangling images:"
    dangling=$(docker images -f "dangling=true" -q 2>/dev/null | wc -l)
    echo "  $dangling dangling image(s)"

    # Old unused images
    echo ""
    echo "Unused images older than ${AGE_DAYS} days:"
    age_filter=$(date -d "${AGE_DAYS} days ago" '+%Y-%m-%dT%H:%M:%S')

    # Get images not used by any container
    used_images=$(docker ps -a --format '{{.Image}}' | sort -u)

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        image_id=$(echo "$line" | awk '{print $1}')
        image_name=$(echo "$line" | awk '{print $2}')
        image_tag=$(echo "$line" | awk '{print $3}')
        created=$(echo "$line" | awk '{print $4}')

        # Skip if image is in use
        full_name="${image_name}:${image_tag}"
        if echo "$used_images" | grep -qE "^(${image_id}|${full_name})$"; then
            continue
        fi

        # Check age
        if [[ "$created" < "$age_filter" ]]; then
            to_remove_images+=("$image_id")
            echo "  ${full_name} (created: ${created:0:10})"
        fi
    done < <(docker images --format "{{.ID}} {{.Repository}} {{.Tag}} {{.CreatedAt}}" 2>/dev/null)

    if [[ ${#to_remove_images[@]} -eq 0 ]] && [[ $dangling -eq 0 ]]; then
        echo "  None found"
    fi
fi

# Find unused volumes
if $CLEAN_VOLUMES; then
    print_header "⚠ Unused Volumes (DANGEROUS)"
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        to_remove_volumes+=("$line")
        # Get volume size
        size=$(docker volume inspect "$line" --format '{{.UsageData.Size}}' 2>/dev/null || echo "unknown")
        echo "  $line (${size} bytes)"
    done < <(docker volume ls -q --filter "dangling=true" 2>/dev/null)

    if [[ ${#to_remove_volumes[@]} -eq 0 ]]; then
        echo "  None found"
    else
        echo ""
        echo "  WARNING: Removing volumes can cause DATA LOSS!"
    fi
fi

# Find unused networks
if $CLEAN_NETWORKS; then
    print_header "Unused Networks"
    # Don't remove default networks
    default_networks="bridge|host|none"

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        [[ "$line" =~ ^($default_networks)$ ]] && continue
        to_remove_networks+=("$line")
        echo "  $line"
    done < <(docker network ls --filter "dangling=true" --format "{{.Name}}" 2>/dev/null)

    if [[ ${#to_remove_networks[@]} -eq 0 ]]; then
        echo "  None found"
    fi
fi

# Summary
print_header "Cleanup Summary"
echo "Containers to remove: ${#to_remove_containers[@]}"
echo "Images to remove:     ${#to_remove_images[@]} (plus dangling)"
echo "Volumes to remove:    ${#to_remove_volumes[@]}"
echo "Networks to remove:   ${#to_remove_networks[@]}"
echo "Build cache:          $([ "$CLEAN_BUILD_CACHE" = true ] && echo "will be pruned" || echo "skipped")"

# Exit if dry run
if $DRY_RUN; then
    print_divider
    log_info "DRY RUN complete - no changes made"
    log_info "Run without --dry-run to perform cleanup"
    exit 0
fi

# Confirm if not forced
if ! $FORCE; then
    echo ""
    read -rp "Proceed with cleanup? [y/N] " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        log_info "Cleanup cancelled"
        exit 0
    fi
fi

# Perform cleanup
print_header "Performing Cleanup"
docker_root=$(docker info --format '{{.DockerRootDir}}' 2>/dev/null || echo "/var/lib/docker")
space_before_bytes=$(df -B1 --output=used "$docker_root" 2>/dev/null | tail -1 | tr -d ' ')

# Remove stopped containers
if $CLEAN_CONTAINERS && [[ ${#to_remove_containers[@]} -gt 0 ]]; then
    log_info "Removing stopped containers..."
    docker container prune -f
fi

# Remove unused images
if $CLEAN_IMAGES; then
    log_info "Removing dangling images..."
    docker image prune -f

    # Remove old unused images
    for image_id in "${to_remove_images[@]}"; do
        log_info "Removing image: $image_id"
        docker rmi "$image_id" 2>/dev/null || log_warn "Could not remove $image_id (may be in use)"
    done
fi

# Remove unused volumes (if enabled)
if $CLEAN_VOLUMES && [[ ${#to_remove_volumes[@]} -gt 0 ]]; then
    log_warn "Removing unused volumes..."
    docker volume prune -f
fi

# Remove unused networks
if $CLEAN_NETWORKS; then
    log_info "Removing unused networks..."
    docker network prune -f
fi

# Remove build cache
if $CLEAN_BUILD_CACHE; then
    log_info "Removing build cache..."
    docker builder prune -f 2>/dev/null || true
fi

# Show results
print_header "Cleanup Complete"
echo ""
echo "Disk usage after cleanup:"
printf "%-15s %10s %12s %15s\n" "TYPE" "COUNT" "SIZE" "RECLAIMABLE"
print_divider 55

while IFS='|' read -r type count size reclaimable; do
    printf "%-15s %10s %12s %15s\n" "$type" "$count" "$size" "$reclaimable"
done < <(get_disk_usage)

space_after_bytes=$(df -B1 --output=used "$docker_root" 2>/dev/null | tail -1 | tr -d ' ')
reclaimed_bytes=$((space_before_bytes - space_after_bytes))
if [[ $reclaimed_bytes -lt 0 ]]; then
    reclaimed_bytes=0
fi
log_success "Cleanup complete — reclaimed $(human_size $reclaimed_bytes)"

exit 0
