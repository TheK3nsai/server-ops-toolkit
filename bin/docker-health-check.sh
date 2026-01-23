#!/usr/bin/env bash
# docker-health-check.sh - Monitor Docker container health and status
#
# Purpose: Check all containers for health status, restart failures,
#          exit codes, and optionally restart unhealthy containers
#
# Usage: ./docker-health-check.sh [--restart] [--json] [--stack NAME]
#        --restart    : Attempt to restart unhealthy/exited containers
#        --json       : Output in JSON format
#        --stack NAME : Only check containers from specific compose stack
#
# Dependencies: docker
#
# Exit codes: 0=all healthy, 1=error, 2=unhealthy containers found

set -euo pipefail

# Source common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "${SCRIPT_DIR}/../lib/common.sh"

# Configuration
DOCKER_ROOT="${DOCKER_ROOT:-/home/kensai/docker}"
AUTO_RESTART=false
JSON_OUTPUT=false
SPECIFIC_STACK=""
RESTART_WAIT=10  # seconds to wait after restart before checking status

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --restart)
            AUTO_RESTART=true
            shift
            ;;
        --json)
            JSON_OUTPUT=true
            shift
            ;;
        --stack)
            SPECIFIC_STACK="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [--restart] [--json] [--stack NAME]"
            echo "  --restart    : Attempt to restart unhealthy/exited containers"
            echo "  --json       : Output in JSON format"
            echo "  --stack NAME : Only check containers from specific stack"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check Docker is available
if ! command -v docker &>/dev/null; then
    log_error "Docker is not installed or not in PATH"
    exit 1
fi

if ! docker info &>/dev/null; then
    log_error "Cannot connect to Docker daemon"
    exit 1
fi

# Initialize tracking arrays
declare -a healthy_containers=()
declare -a unhealthy_containers=()
declare -a exited_containers=()
declare -a restarting_containers=()
declare -a no_healthcheck=()
declare -a restarted_containers=()
issues_found=0

# Get container list
if [[ -n "$SPECIFIC_STACK" ]]; then
    # Filter by compose project
    container_filter="label=com.docker.compose.project=${SPECIFIC_STACK}"
    containers=$(docker ps -a --filter "$container_filter" --format "{{.Names}}")
else
    containers=$(docker ps -a --format "{{.Names}}")
fi

# Check each container
for container in $containers; do
    # Get container status info
    status=$(docker inspect --format '{{.State.Status}}' "$container" 2>/dev/null) || continue
    health=$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container" 2>/dev/null) || health="none"
    restarts=$(docker inspect --format '{{.RestartCount}}' "$container" 2>/dev/null) || restarts="0"
    exit_code=$(docker inspect --format '{{.State.ExitCode}}' "$container" 2>/dev/null) || exit_code="0"
    image=$(docker inspect --format '{{.Config.Image}}' "$container" 2>/dev/null) || image="unknown"

    # Get uptime/started time
    started=$(docker inspect --format '{{.State.StartedAt}}' "$container" 2>/dev/null) || started=""

    # Categorize container
    case "$status" in
        running)
            case "$health" in
                healthy)
                    healthy_containers+=("${container}|${image}|${restarts}|${started}")
                    ;;
                unhealthy)
                    unhealthy_containers+=("${container}|${image}|${restarts}|${started}")
                    issues_found=1
                    ;;
                starting)
                    # Still starting up, not an issue yet
                    healthy_containers+=("${container}|${image}|${restarts}|${started}|starting")
                    ;;
                none)
                    no_healthcheck+=("${container}|${image}|${restarts}|${started}")
                    ;;
            esac
            ;;
        exited)
            # Check if it's a one-shot container (cron jobs, etc.)
            restart_policy=$(docker inspect --format '{{.HostConfig.RestartPolicy.Name}}' "$container" 2>/dev/null) || restart_policy=""
            if [[ "$restart_policy" == "no" ]] && [[ "$exit_code" == "0" ]]; then
                # Completed successfully, likely a one-shot
                no_healthcheck+=("${container}|${image}|exited-ok|${started}")
            else
                exited_containers+=("${container}|${image}|${exit_code}|${started}")
                issues_found=1
            fi
            ;;
        restarting)
            restarting_containers+=("${container}|${image}|${restarts}|${started}")
            issues_found=1
            ;;
        *)
            # Other states (created, paused, dead)
            exited_containers+=("${container}|${image}|${status}|${started}")
            issues_found=1
            ;;
    esac
done

# Function to restart a container
restart_container() {
    local container="$1"
    local project

    # Try to get compose project for proper restart
    project=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$container" 2>/dev/null) || project=""
    service=$(docker inspect --format '{{index .Config.Labels "com.docker.compose.service"}}' "$container" 2>/dev/null) || service=""

    if [[ -n "$project" ]] && [[ -n "$service" ]] && [[ -d "${DOCKER_ROOT}/${project}" ]]; then
        # Use docker compose for proper restart
        log_info "Restarting $container via docker compose..."
        if (cd "${DOCKER_ROOT}/${project}" && docker compose restart "$service"); then
            return 0
        fi
    fi

    # Fallback to docker restart
    log_info "Restarting $container via docker restart..."
    docker restart "$container"
}

# Auto-restart if enabled
if $AUTO_RESTART && [[ $issues_found -eq 1 ]]; then
    # Restart unhealthy containers
    for entry in "${unhealthy_containers[@]}"; do
        container="${entry%%|*}"
        if restart_container "$container"; then
            restarted_containers+=("$container")
            log_success "Restarted: $container"
        else
            log_error "Failed to restart: $container"
        fi
    done

    # Restart exited containers (except successful one-shots)
    for entry in "${exited_containers[@]}"; do
        container="${entry%%|*}"
        if restart_container "$container"; then
            restarted_containers+=("$container")
            log_success "Restarted: $container"
        else
            log_error "Failed to restart: $container"
        fi
    done

    # Wait and recheck
    if [[ ${#restarted_containers[@]} -gt 0 ]]; then
        log_info "Waiting ${RESTART_WAIT}s for containers to stabilize..."
        sleep "$RESTART_WAIT"
    fi
fi

# Calculate totals
total_containers=$((${#healthy_containers[@]} + ${#unhealthy_containers[@]} + ${#exited_containers[@]} + ${#restarting_containers[@]} + ${#no_healthcheck[@]}))

# Output results
if $JSON_OUTPUT; then
    cat <<EOF
{
  "timestamp": "$(date -Iseconds)",
  "summary": {
    "total": $total_containers,
    "healthy": ${#healthy_containers[@]},
    "unhealthy": ${#unhealthy_containers[@]},
    "exited": ${#exited_containers[@]},
    "restarting": ${#restarting_containers[@]},
    "no_healthcheck": ${#no_healthcheck[@]},
    "restarted": ${#restarted_containers[@]}
  },
  "unhealthy": [$(printf '"%s",' "${unhealthy_containers[@]%%|*}" 2>/dev/null | sed 's/,$//')],
  "exited": [$(printf '"%s",' "${exited_containers[@]%%|*}" 2>/dev/null | sed 's/,$//')],
  "issues_found": $([ $issues_found -eq 1 ] && echo "true" || echo "false")
}
EOF
else
    print_header "Docker Container Health Check"
    echo "Generated: $(date)"
    [[ -n "$SPECIFIC_STACK" ]] && echo "Stack: $SPECIFIC_STACK"

    print_header "Summary"
    echo "Total containers:     $total_containers"
    echo "Healthy:              ${#healthy_containers[@]}"
    echo "Unhealthy:            ${#unhealthy_containers[@]}"
    echo "Exited/Stopped:       ${#exited_containers[@]}"
    echo "Restarting:           ${#restarting_containers[@]}"
    echo "No healthcheck:       ${#no_healthcheck[@]}"

    if [[ ${#restarted_containers[@]} -gt 0 ]]; then
        echo "Restarted this run:   ${#restarted_containers[@]}"
    fi

    # Show healthy containers
    if [[ ${#healthy_containers[@]} -gt 0 ]]; then
        print_header "Healthy Containers"
        printf "%-25s %-40s %s\n" "CONTAINER" "IMAGE" "RESTARTS"
        print_divider 75
        for entry in "${healthy_containers[@]}"; do
            IFS='|' read -r name image restarts _ <<< "$entry"
            printf "%-25s %-40s %s\n" "${name:0:24}" "${image:0:39}" "$restarts"
        done
    fi

    # Show containers without healthcheck
    if [[ ${#no_healthcheck[@]} -gt 0 ]]; then
        print_header "Running (No Healthcheck)"
        printf "%-25s %-40s %s\n" "CONTAINER" "IMAGE" "STATUS"
        print_divider 75
        for entry in "${no_healthcheck[@]}"; do
            IFS='|' read -r name image status _ <<< "$entry"
            printf "%-25s %-40s %s\n" "${name:0:24}" "${image:0:39}" "${status:-running}"
        done
    fi

    # Show unhealthy containers
    if [[ ${#unhealthy_containers[@]} -gt 0 ]]; then
        print_header "⚠ Unhealthy Containers"
        for entry in "${unhealthy_containers[@]}"; do
            IFS='|' read -r name image restarts started <<< "$entry"
            echo "  $name"
            echo "    Image: $image"
            echo "    Restarts: $restarts"
            # Get last health check output
            health_log=$(docker inspect --format '{{if .State.Health}}{{range .State.Health.Log}}{{.Output}}{{end}}{{end}}' "$name" 2>/dev/null | tail -c 200)
            [[ -n "$health_log" ]] && echo "    Last health output: ${health_log:0:100}..."
            echo ""
        done
    fi

    # Show exited containers
    if [[ ${#exited_containers[@]} -gt 0 ]]; then
        print_header "⚠ Exited Containers"
        for entry in "${exited_containers[@]}"; do
            IFS='|' read -r name image exit_code started <<< "$entry"
            echo "  $name"
            echo "    Image: $image"
            echo "    Exit code: $exit_code"
            # Get last few log lines
            last_logs=$(docker logs --tail 3 "$name" 2>&1 | head -c 200)
            [[ -n "$last_logs" ]] && echo "    Last logs: ${last_logs:0:100}..."
            echo ""
        done
    fi

    # Show restarting containers
    if [[ ${#restarting_containers[@]} -gt 0 ]]; then
        print_header "⚠ Containers in Restart Loop"
        for entry in "${restarting_containers[@]}"; do
            IFS='|' read -r name image restarts _ <<< "$entry"
            echo "  $name (restarts: $restarts)"
        done
    fi

    # Show restarted containers
    if [[ ${#restarted_containers[@]} -gt 0 ]]; then
        print_header "Restarted This Run"
        for container in "${restarted_containers[@]}"; do
            new_status=$(docker inspect --format '{{.State.Status}}' "$container" 2>/dev/null) || new_status="unknown"
            echo "  $container -> $new_status"
        done
    fi

    print_divider
    if [[ $issues_found -eq 1 ]]; then
        log_warn "Container issues detected"
        if ! $AUTO_RESTART; then
            echo "Run with --restart to attempt automatic recovery"
        fi
    else
        log_success "All containers healthy"
    fi
fi

# Notify if configured
if [[ -n "${UPTIME_KUMA_DOCKER_PUSH:-}" ]]; then
    if [[ $issues_found -eq 1 ]]; then
        notify_uptime_kuma "$UPTIME_KUMA_DOCKER_PUSH" "down" "${#unhealthy_containers[@]} unhealthy, ${#exited_containers[@]} exited"
    else
        notify_uptime_kuma "$UPTIME_KUMA_DOCKER_PUSH" "up" "All ${total_containers} containers healthy"
    fi
fi

exit $((issues_found * 2))
