#!/usr/bin/env bash
#
# Coyote - Repository Security Watcher Loop
#
# Polls a target repo for new commits. When changes are detected,
# pulls latest code and runs the security scanner.
#
# Usage:
#   ./coyote.sh                        # Use config.yaml defaults
#   ./coyote.sh --repo-url <url>       # Watch a specific repo
#   ./coyote.sh --local-path <path>    # Scan a local repo
#   ./coyote.sh --interval <seconds>   # Set poll interval
#   ./coyote.sh --once                 # Run scan once and exit
#   ./coyote.sh --interactive          # Launch interactive TUI
#

set -euo pipefail

# ─── Defaults ───────────────────────────────────────────────────────
REPO_URL=""
BRANCH="main"
LOCAL_PATH="./watched_repo"
POLL_INTERVAL=60
RUN_ONCE=false
INTERACTIVE=false
CONFIG_FILE="config.yaml"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPORT=false
SAVE_BASELINE=false
DIFF_MODE=false
BASELINE_PATH=".coyote-baseline.json"
FAIL_ON_NEW=false
NOTIFY=false
SLACK_WEBHOOK=""
DISCORD_WEBHOOK=""
HISTORY_SCAN=false
MAX_COMMITS=100
ENTROPY_SCAN=false
ENTROPY_THRESHOLD="4.5"
IGNORE_FILE=""
NO_IGNORE=false
SARIF_OUTPUT=""

# ─── Colors ─────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# ─── Coyote ASCII ──────────────────────────────────────────────────
print_coyote() {
    echo -e "${CYAN}"
    echo '     /|      |\'
    echo '    / |      | \'
    echo '   |   \    /   |'
    echo '   |    \  /    |'
    echo '   |  o  \/  o  |'
    echo '   |     /\     |'
    echo '    \   /  \   /'
    echo '     | | <> | |'
    echo '     |  \__/  |'
    echo '      \_|  |_/'
    echo -e "${NC}"
}

print_coyote_alert() {
    echo -e "${RED}"
    echo '     /|  !!  |\'
    echo '    / |      | \'
    echo '   |   \    /   |'
    echo '   |    \  /    |'
    echo '   |  O  \/  O  |'
    echo '   |     /\     |'
    echo '    \   /^^\   /'
    echo '     | | <> | |'
    echo '     |  \__/  |'
    echo '      \_|  |_/'
    echo -e "${NC}"
}

print_coyote_clear() {
    echo -e "${GREEN}"
    echo '     /|      |\'
    echo '    / |      | \'
    echo '   |   \    /   |'
    echo '   |    \  /    |'
    echo '   |  ^  \/  ^  |'
    echo '   |     /\     |'
    echo '    \   /  \   /'
    echo '     | |\__/| |'
    echo '     |  \w /  |'
    echo '      \_|  |_/'
    echo -e "${NC}"
}

# ─── Logging ────────────────────────────────────────────────────────
log_info()  { echo -e "${CYAN}[COYOTE]${NC} $(date '+%H:%M:%S') $*"; }
log_warn()  { echo -e "${YELLOW}[COYOTE]${NC} $(date '+%H:%M:%S') $*"; }
log_error() { echo -e "${RED}[COYOTE]${NC} $(date '+%H:%M:%S') $*"; }
log_ok()    { echo -e "${GREEN}[COYOTE]${NC} $(date '+%H:%M:%S') $*"; }

# ─── Parse Arguments ───────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --repo-url)
                REPO_URL="$2"; shift 2 ;;
            --branch)
                BRANCH="$2"; shift 2 ;;
            --local-path)
                LOCAL_PATH="$2"; shift 2 ;;
            --interval)
                POLL_INTERVAL="$2"; shift 2 ;;
            --once)
                RUN_ONCE=true; shift ;;
            --interactive|-i)
                INTERACTIVE=true; shift ;;
            --config)
                CONFIG_FILE="$2"; shift 2 ;;
            --report|-r)
                REPORT=true; shift ;;
            --save-baseline)
                SAVE_BASELINE=true; shift ;;
            --diff)
                DIFF_MODE=true; shift ;;
            --baseline-path)
                BASELINE_PATH="$2"; shift 2 ;;
            --fail-on-new)
                FAIL_ON_NEW=true; shift ;;
            --notify)
                NOTIFY=true; shift ;;
            --slack-webhook)
                SLACK_WEBHOOK="$2"; shift 2 ;;
            --discord-webhook)
                DISCORD_WEBHOOK="$2"; shift 2 ;;
            --history)
                HISTORY_SCAN=true; shift ;;
            --max-commits)
                MAX_COMMITS="$2"; shift 2 ;;
            --entropy)
                ENTROPY_SCAN=true; shift ;;
            --entropy-threshold)
                ENTROPY_THRESHOLD="$2"; shift 2 ;;
            --ignore-file)
                IGNORE_FILE="$2"; shift 2 ;;
            --no-ignore)
                NO_IGNORE=true; shift ;;
            --sarif)
                SARIF_OUTPUT="$2"; shift 2 ;;
            --help|-h)
                echo "Coyote - Repository Security Watcher"
                echo ""
                echo "Usage: ./coyote.sh [OPTIONS]"
                echo ""
                echo "Options:"
                echo "  --repo-url <url>     GitHub repo URL to watch"
                echo "  --branch <name>      Branch to watch (default: main)"
                echo "  --local-path <path>  Local clone path (default: ./watched_repo)"
                echo "  --interval <sec>     Poll interval in seconds (default: 60)"
                echo "  --once               Run scan once and exit"
                echo "  --interactive, -i    Launch interactive TUI"
                echo "  --report, -r         Save reports after scan"
                echo "  --config <file>      Config file path (default: config.yaml)"
                echo ""
                echo "Baseline/Diff Options:"
                echo "  --save-baseline      Save scan as baseline for future comparisons"
                echo "  --diff               Compare scan against baseline (show new/fixed)"
                echo "  --baseline-path      Path to baseline file (default: .coyote-baseline.json)"
                echo "  --fail-on-new        Exit with code 1 if new findings (for CI)"
                echo ""
                echo "Notification Options:"
                echo "  --notify             Enable webhook notifications (uses config file)"
                echo "  --slack-webhook URL  Slack webhook URL (overrides config)"
                echo "  --discord-webhook URL Discord webhook URL (overrides config)"
                echo ""
                echo "History Scanning:"
                echo "  --history            Scan git history for secrets in past commits"
                echo "  --max-commits N      Max commits to scan (default: 100)"
                echo ""
                echo "Entropy Detection:"
                echo "  --entropy            Enable entropy-based secret detection"
                echo "  --entropy-threshold  Entropy threshold (default: 4.5, lower = more sensitive)"
                echo ""
                echo "Suppression:"
                echo "  --ignore-file FILE   Path to ignore file (default: .coyote-ignore)"
                echo "  --no-ignore          Disable suppression, scan everything"
                echo ""
                echo "Output Formats:"
                echo "  --sarif FILE         Output results in SARIF format to FILE (use - for stdout)"
                echo ""
                echo "  --help, -h           Show this help"
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
}

# ─── Load Config from YAML (basic parsing) ─────────────────────────
load_config() {
    if [[ -f "$CONFIG_FILE" ]]; then
        log_info "Loading config from ${CONFIG_FILE}"

        # Only override if not set via CLI
        if [[ -z "$REPO_URL" ]]; then
            REPO_URL=$(python3 -c "
import yaml, sys
try:
    c = yaml.safe_load(open('$CONFIG_FILE'))
    print(c.get('target',{}).get('repo_url',''))
except: pass
" 2>/dev/null || echo "")
        fi

        if [[ "$LOCAL_PATH" == "./watched_repo" ]]; then
            val=$(python3 -c "
import yaml
try:
    c = yaml.safe_load(open('$CONFIG_FILE'))
    print(c.get('target',{}).get('local_path',''))
except: pass
" 2>/dev/null || echo "")
            [[ -n "$val" ]] && LOCAL_PATH="$val"
        fi

        if [[ "$BRANCH" == "main" ]]; then
            val=$(python3 -c "
import yaml
try:
    c = yaml.safe_load(open('$CONFIG_FILE'))
    print(c.get('target',{}).get('branch',''))
except: pass
" 2>/dev/null || echo "")
            [[ -n "$val" ]] && BRANCH="$val"
        fi

        if [[ "$POLL_INTERVAL" == "60" ]]; then
            val=$(python3 -c "
import yaml
try:
    c = yaml.safe_load(open('$CONFIG_FILE'))
    print(c.get('polling',{}).get('interval_seconds',''))
except: pass
" 2>/dev/null || echo "")
            [[ -n "$val" ]] && POLL_INTERVAL="$val"
        fi
    fi
}

# ─── Clone or Validate Repo ────────────────────────────────────────
setup_repo() {
    if [[ -d "$LOCAL_PATH/.git" ]]; then
        log_info "Repository already cloned at ${LOCAL_PATH}"
        return 0
    fi

    if [[ -n "$REPO_URL" ]]; then
        log_info "Cloning ${REPO_URL} into ${LOCAL_PATH}..."
        git clone --branch "$BRANCH" --single-branch "$REPO_URL" "$LOCAL_PATH"
        log_ok "Clone complete."
    elif [[ -d "$LOCAL_PATH" ]]; then
        log_info "Using existing directory: ${LOCAL_PATH}"
    else
        log_error "No repo URL provided and ${LOCAL_PATH} does not exist."
        log_error "Use --repo-url <url> or --local-path <path>"
        exit 1
    fi
}

# ─── Check for New Commits ─────────────────────────────────────────
check_new_commits() {
    local local_head remote_head

    # Fetch latest from remote (if remote exists)
    if git -C "$LOCAL_PATH" remote get-url origin &>/dev/null; then
        git -C "$LOCAL_PATH" fetch origin "$BRANCH" --quiet 2>/dev/null || true
        local_head=$(git -C "$LOCAL_PATH" rev-parse HEAD 2>/dev/null || echo "none")
        remote_head=$(git -C "$LOCAL_PATH" rev-parse "origin/$BRANCH" 2>/dev/null || echo "none")

        if [[ "$local_head" != "$remote_head" && "$remote_head" != "none" ]]; then
            return 0  # New commits detected
        fi
        return 1  # No new commits
    fi

    # No remote -- always scan on first run, then skip
    return 1
}

# ─── Pull Latest ───────────────────────────────────────────────────
pull_latest() {
    log_info "Pulling latest changes..."
    git -C "$LOCAL_PATH" pull origin "$BRANCH" --quiet 2>/dev/null || {
        log_warn "Pull failed, trying reset..."
        git -C "$LOCAL_PATH" fetch origin "$BRANCH" --quiet
        git -C "$LOCAL_PATH" reset --hard "origin/$BRANCH" --quiet
    }
    local commit
    commit=$(git -C "$LOCAL_PATH" rev-parse --short HEAD 2>/dev/null || echo "unknown")
    log_ok "Updated to commit ${commit}"
}

# ─── Run Security Scan ─────────────────────────────────────────────
run_scan() {
    log_info "Running security scan..."

    local scan_args=("--repo" "$LOCAL_PATH" "--config" "$CONFIG_FILE")
    if [[ "$REPORT" == "true" ]]; then
        scan_args+=("--report")
    fi
    if [[ "$SAVE_BASELINE" == "true" ]]; then
        scan_args+=("--save-baseline")
    fi
    if [[ "$DIFF_MODE" == "true" ]]; then
        scan_args+=("--diff")
    fi
    if [[ "$BASELINE_PATH" != ".coyote-baseline.json" ]]; then
        scan_args+=("--baseline-path" "$BASELINE_PATH")
    fi
    if [[ "$FAIL_ON_NEW" == "true" ]]; then
        scan_args+=("--fail-on-new")
    fi
    if [[ "$NOTIFY" == "true" ]]; then
        scan_args+=("--notify")
    fi
    if [[ -n "$SLACK_WEBHOOK" ]]; then
        scan_args+=("--slack-webhook" "$SLACK_WEBHOOK")
    fi
    if [[ -n "$DISCORD_WEBHOOK" ]]; then
        scan_args+=("--discord-webhook" "$DISCORD_WEBHOOK")
    fi
    if [[ "$HISTORY_SCAN" == "true" ]]; then
        scan_args+=("--history")
        scan_args+=("--max-commits" "$MAX_COMMITS")
    fi
    if [[ "$ENTROPY_SCAN" == "true" ]]; then
        scan_args+=("--entropy")
        scan_args+=("--entropy-threshold" "$ENTROPY_THRESHOLD")
    fi
    if [[ -n "$IGNORE_FILE" ]]; then
        scan_args+=("--ignore-file" "$IGNORE_FILE")
    fi
    if [[ "$NO_IGNORE" == "true" ]]; then
        scan_args+=("--no-ignore")
    fi
    if [[ -n "$SARIF_OUTPUT" ]]; then
        scan_args+=("--sarif" "$SARIF_OUTPUT")
    fi

    python3 -m coyote.tui "${scan_args[@]}"

    local exit_code=$?
    if [[ $exit_code -eq 0 ]]; then
        log_ok "Scan complete."
    else
        log_error "Scan failed with exit code ${exit_code}"
    fi
    return $exit_code
}

# ─── Main Loop ──────────────────────────────────────────────────────
main() {
    parse_args "$@"
    load_config

    echo -e "${BOLD}${CYAN}"
    echo "╔═══════════════════════════════════════════╗"
    echo "║  COYOTE v1.0 - Repo Security Scanner     ║"
    echo "╚═══════════════════════════════════════════╝"
    echo -e "${NC}"
    print_coyote

    # Interactive mode: launch the TUI directly
    if [[ "$INTERACTIVE" == "true" ]]; then
        setup_repo
        log_info "Launching interactive TUI..."
        python3 -m coyote.tui --interactive --repo "$LOCAL_PATH" --config "$CONFIG_FILE"
        exit $?
    fi

    setup_repo

    # Run once mode
    if [[ "$RUN_ONCE" == "true" ]]; then
        log_info "Running single scan..."
        run_scan
        exit $?
    fi

    # Watcher loop
    log_info "Starting watcher loop (polling every ${POLL_INTERVAL}s)..."
    log_info "Watching: ${REPO_URL:-$LOCAL_PATH} (branch: ${BRANCH})"
    log_info "Press Ctrl+C to stop."
    echo ""

    local first_run=true

    trap 'echo ""; log_info "Shutting down..."; print_coyote_clear; exit 0' INT TERM

    while true; do
        if [[ "$first_run" == "true" ]]; then
            log_info "Running initial scan..."
            run_scan || true
            first_run=false
        else
            if check_new_commits; then
                log_warn "New commits detected!"
                print_coyote_alert
                pull_latest
                run_scan || true
            else
                log_info "No new commits. Sleeping ${POLL_INTERVAL}s..."
            fi
        fi

        sleep "$POLL_INTERVAL"
    done
}

main "$@"
