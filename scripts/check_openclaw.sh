#!/usr/bin/env bash
# ClawSafe - OpenClaw Configuration Security Audit
# Specifically designed for OpenClaw Gateway deployments
# Supports: Linux, macOS, containers
#
# IMPORTANT: This script does NOT assume any hardcoded paths.
# It dynamically discovers the OpenClaw installation using multiple strategies:
#   1. `openclaw` CLI commands (most reliable)
#   2. Environment variables (OPENCLAW_HOME, OPENCLAW_STATE_DIR, OPENCLAW_CONFIG_PATH)
#   3. Running process inspection
#   4. Common locations as last resort (never assumed to be correct)
#
# Usage:
#   bash check_openclaw.sh                  # Auto-discover everything
#   bash check_openclaw.sh /path/to/home    # Explicit OpenClaw home override
#
# Output: JSON lines, one finding per line

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/utils.sh"

# ============================================================
# Path Discovery Engine
# Discovers OpenClaw paths without assuming anything
# ============================================================

# Resolved paths (populated by discover_paths)
OPENCLAW_HOME_DIR=""
CONFIG_FILE=""
OPENCLAW_CLI=""
DISCOVERY_METHOD=""

# Try to find the openclaw CLI binary
find_openclaw_cli() {
    # Method 1: Already in PATH
    if command -v openclaw &>/dev/null; then
        OPENCLAW_CLI="openclaw"
        return 0
    fi

    # Method 2: npx (if installed via npm)
    if command -v npx &>/dev/null; then
        if npx --yes openclaw --version &>/dev/null 2>&1; then
            OPENCLAW_CLI="npx openclaw"
            return 0
        fi
    fi

    # Method 3: Check running processes for the binary path
    local proc_path=""
    if command -v pgrep &>/dev/null; then
        local pids
        pids=$(pgrep -f "openclaw" 2>/dev/null || true)
        if [ -n "$pids" ]; then
            local first_pid
            first_pid=$(echo "$pids" | head -1)
            if [ "$(uname -s)" = "Darwin" ]; then
                proc_path=$(ps -p "$first_pid" -o command= 2>/dev/null | awk '{print $1}' || true)
            else
                proc_path=$(readlink -f "/proc/${first_pid}/exe" 2>/dev/null || true)
            fi
        fi
    fi
    if [ -n "$proc_path" ] && [ -x "$proc_path" ]; then
        OPENCLAW_CLI="$proc_path"
        return 0
    fi

    return 1
}

# Discover the state/home directory using all available strategies
discover_state_dir() {
    # Strategy 1: Explicit argument passed to this script
    if [ -n "${1:-}" ] && [ -d "${1:-}" ]; then
        OPENCLAW_HOME_DIR="$1"
        DISCOVERY_METHOD="explicit_argument"
        return 0
    fi

    # Strategy 2: Use `openclaw` CLI to query the actual config path
    if [ -n "$OPENCLAW_CLI" ]; then
        # Try `openclaw config get` to discover the live config path
        # The CLI knows exactly where everything is
        local cli_state_dir=""

        # Method A: Ask openclaw for a known config value and infer state dir from the output
        # openclaw doctor usually outputs path information
        cli_state_dir=$($OPENCLAW_CLI config get agents.defaults.workspace 2>/dev/null | head -1 || true)

        # Method B: If openclaw supports `config path` or similar
        if [ -z "$cli_state_dir" ]; then
            cli_state_dir=$($OPENCLAW_CLI config path 2>/dev/null | head -1 || true)
        fi

        # If we got a config file path, extract the parent directory
        if [ -n "$cli_state_dir" ] && echo "$cli_state_dir" | grep -q "openclaw"; then
            local inferred_dir
            inferred_dir=$(dirname "$cli_state_dir" 2>/dev/null || true)
            if [ -n "$inferred_dir" ] && [ -d "$inferred_dir" ]; then
                OPENCLAW_HOME_DIR="$inferred_dir"
                DISCOVERY_METHOD="cli_config_path"
                return 0
            fi
        fi
    fi

    # Strategy 3: Environment variables (official OpenClaw env vars)
    # OPENCLAW_CONFIG_PATH points directly to the config file
    if [ -n "${OPENCLAW_CONFIG_PATH:-}" ] && [ -f "$OPENCLAW_CONFIG_PATH" ]; then
        OPENCLAW_HOME_DIR=$(dirname "$OPENCLAW_CONFIG_PATH")
        DISCOVERY_METHOD="env_OPENCLAW_CONFIG_PATH"
        return 0
    fi

    # OPENCLAW_STATE_DIR points to the state directory
    if [ -n "${OPENCLAW_STATE_DIR:-}" ] && [ -d "$OPENCLAW_STATE_DIR" ]; then
        OPENCLAW_HOME_DIR="$OPENCLAW_STATE_DIR"
        DISCOVERY_METHOD="env_OPENCLAW_STATE_DIR"
        return 0
    fi

    # OPENCLAW_HOME overrides all path resolution
    if [ -n "${OPENCLAW_HOME:-}" ]; then
        # OPENCLAW_HOME replaces $HOME, so state dir is at $OPENCLAW_HOME/.openclaw
        local candidate="${OPENCLAW_HOME}/.openclaw"
        if [ -d "$candidate" ]; then
            OPENCLAW_HOME_DIR="$candidate"
            DISCOVERY_METHOD="env_OPENCLAW_HOME"
            return 0
        fi
        # It might also be the direct state dir
        if [ -f "${OPENCLAW_HOME}/openclaw.json" ]; then
            OPENCLAW_HOME_DIR="$OPENCLAW_HOME"
            DISCOVERY_METHOD="env_OPENCLAW_HOME_direct"
            return 0
        fi
    fi

    # Strategy 4: Inspect running process working directory
    if command -v pgrep &>/dev/null; then
        local pids
        pids=$(pgrep -f "openclaw" 2>/dev/null || true)
        if [ -n "$pids" ]; then
            local first_pid
            first_pid=$(echo "$pids" | head -1)
            # Check the process environment for OPENCLAW_STATE_DIR
            if [ -f "/proc/${first_pid}/environ" ]; then
                local proc_state
                proc_state=$(tr '\0' '\n' < "/proc/${first_pid}/environ" 2>/dev/null \
                    | grep '^OPENCLAW_STATE_DIR=' | cut -d= -f2- || true)
                if [ -n "$proc_state" ] && [ -d "$proc_state" ]; then
                    OPENCLAW_HOME_DIR="$proc_state"
                    DISCOVERY_METHOD="process_environ"
                    return 0
                fi
                local proc_home
                proc_home=$(tr '\0' '\n' < "/proc/${first_pid}/environ" 2>/dev/null \
                    | grep '^OPENCLAW_HOME=' | cut -d= -f2- || true)
                if [ -n "$proc_home" ]; then
                    local candidate="${proc_home}/.openclaw"
                    if [ -d "$candidate" ]; then
                        OPENCLAW_HOME_DIR="$candidate"
                        DISCOVERY_METHOD="process_environ_HOME"
                        return 0
                    fi
                fi
            fi

            # Check /proc/<pid>/cwd for clues (Linux only)
            if [ -d "/proc/${first_pid}/cwd" ]; then
                local cwd_link
                cwd_link=$(readlink -f "/proc/${first_pid}/cwd" 2>/dev/null || true)
                if [ -n "$cwd_link" ] && [ -f "${cwd_link}/openclaw.json" ]; then
                    OPENCLAW_HOME_DIR="$cwd_link"
                    DISCOVERY_METHOD="process_cwd"
                    return 0
                fi
            fi
        fi
    fi

    # Strategy 5: Search filesystem for openclaw.json (use `find` with depth limit)
    # Only look in common parent directories, NEVER scan from /
    local search_roots=()
    [ -n "${HOME:-}" ] && search_roots+=("$HOME")
    [ -n "${XDG_CONFIG_HOME:-}" ] && search_roots+=("$XDG_CONFIG_HOME")

    for root in "${search_roots[@]}"; do
        [ -d "$root" ] || continue
        local found
        found=$(find "$root" -maxdepth 3 -name "openclaw.json" -type f 2>/dev/null | head -1 || true)
        if [ -n "$found" ]; then
            OPENCLAW_HOME_DIR=$(dirname "$found")
            DISCOVERY_METHOD="filesystem_search"
            return 0
        fi
    done

    return 1
}

# Discover the config file path
discover_config_file() {
    # Priority 1: OPENCLAW_CONFIG_PATH env var
    if [ -n "${OPENCLAW_CONFIG_PATH:-}" ] && [ -f "$OPENCLAW_CONFIG_PATH" ]; then
        CONFIG_FILE="$OPENCLAW_CONFIG_PATH"
        return 0
    fi

    # Priority 2: Use CLI to get config
    if [ -n "$OPENCLAW_CLI" ]; then
        # Try to dump the whole config - this gives us the actual running config
        local config_dump
        config_dump=$($OPENCLAW_CLI gateway call config.get --params '{}' 2>/dev/null || true)
        if [ -n "$config_dump" ]; then
            # Write to a temp file for analysis
            CONFIG_FILE=$(mktemp /tmp/clawsafe-config-XXXXXX.json)
            echo "$config_dump" > "$CONFIG_FILE"
            CLEANUP_CONFIG=true
            return 0
        fi
    fi

    # Priority 3: Look in the discovered state directory
    if [ -n "$OPENCLAW_HOME_DIR" ] && [ -f "${OPENCLAW_HOME_DIR}/openclaw.json" ]; then
        CONFIG_FILE="${OPENCLAW_HOME_DIR}/openclaw.json"
        return 0
    fi

    return 1
}

# Cleanup temp files on exit
CLEANUP_CONFIG=false
cleanup() {
    if [ "$CLEANUP_CONFIG" = true ] && [ -n "$CONFIG_FILE" ] && [ -f "$CONFIG_FILE" ]; then
        rm -f "$CONFIG_FILE" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# ============================================================
# Helper: read a JSON/JSON5 value (best-effort, no jq dependency)
# ============================================================
config_grep() {
    local pattern="$1"
    if [ -n "$CONFIG_FILE" ] && [ -f "$CONFIG_FILE" ]; then
        grep -iE "$pattern" "$CONFIG_FILE" 2>/dev/null || true
    fi
}

config_file_exists() {
    [ -n "$CONFIG_FILE" ] && [ -f "$CONFIG_FILE" ]
}

# ============================================================
# CHECK 0: Path Discovery Report
# Always emit discovery metadata so the user knows what was found
# ============================================================
emit_discovery_report() {
    if [ -z "$OPENCLAW_HOME_DIR" ]; then
        add_finding "INFO" "OC000" "OpenClaw installation not detected" \
            "Could not discover OpenClaw state directory via CLI, environment variables, running processes, or filesystem search. Checked: OPENCLAW_CONFIG_PATH, OPENCLAW_STATE_DIR, OPENCLAW_HOME env vars; openclaw CLI; running processes; filesystem under \$HOME (depth 3)." \
            "N/A" \
            "If OpenClaw is installed, set OPENCLAW_STATE_DIR or OPENCLAW_CONFIG_PATH environment variable, or ensure 'openclaw' is in PATH, then re-run."
        return 1
    fi

    add_finding "INFO" "OC000" "OpenClaw detected (discovery method: ${DISCOVERY_METHOD})" \
        "State directory: ${OPENCLAW_HOME_DIR}, Config file: ${CONFIG_FILE:-not found}, CLI: ${OPENCLAW_CLI:-not found}" \
        "$OPENCLAW_HOME_DIR" \
        "Discovery used: ${DISCOVERY_METHOD}. Override with OPENCLAW_STATE_DIR or OPENCLAW_CONFIG_PATH env vars if incorrect."
    return 0
}

# ============================================================
# CHECK 1: OpenClaw directory/file permissions
# ============================================================
check_home_permissions() {
    [ -d "$OPENCLAW_HOME_DIR" ] || return

    local os_type perms
    os_type=$(uname -s)

    # Check state directory permissions
    if [ "$os_type" = "Darwin" ]; then
        perms=$(stat -f "%OLp" "$OPENCLAW_HOME_DIR" 2>/dev/null || echo "000")
    else
        perms=$(stat -c "%a" "$OPENCLAW_HOME_DIR" 2>/dev/null || echo "000")
    fi

    if [ "$perms" != "700" ]; then
        add_finding "HIGH" "OC001" "OpenClaw state directory permissions too open" \
            "State directory has permissions ${perms}, should be 700. Contains credentials, sessions, and config." \
            "$OPENCLAW_HOME_DIR" \
            "Run: chmod 700 ${OPENCLAW_HOME_DIR}"
    fi

    # Check config file permissions
    if config_file_exists && [ "$CLEANUP_CONFIG" = false ]; then
        if [ "$os_type" = "Darwin" ]; then
            perms=$(stat -f "%OLp" "$CONFIG_FILE" 2>/dev/null || echo "000")
        else
            perms=$(stat -c "%a" "$CONFIG_FILE" 2>/dev/null || echo "000")
        fi
        local other_perms="${perms: -1}"
        if [ "$other_perms" -ge 4 ] 2>/dev/null; then
            add_finding "HIGH" "OC001" "OpenClaw config file permissions too open" \
                "Config file has permissions ${perms}, readable by others. Contains secrets and auth config." \
                "$CONFIG_FILE" \
                "Run: chmod 600 ${CONFIG_FILE}"
        fi
    fi

    # Discover and check auth profiles (search dynamically, don't assume paths)
    while IFS= read -r authfile; do
        [ -z "$authfile" ] && continue
        if [ "$os_type" = "Darwin" ]; then
            perms=$(stat -f "%OLp" "$authfile" 2>/dev/null || echo "000")
        else
            perms=$(stat -c "%a" "$authfile" 2>/dev/null || echo "000")
        fi
        local other_perms="${perms: -1}"
        if [ "$other_perms" -ge 4 ] 2>/dev/null; then
            add_finding "HIGH" "OC001" "Auth profile file permissions too open" \
                "Auth profiles file has permissions ${perms}, may expose API keys" \
                "$authfile" \
                "Run: chmod 600 ${authfile}"
        fi
    done < <(find "$OPENCLAW_HOME_DIR" -name "auth-profiles.json" -type f 2>/dev/null || true)

    # Check credential files (search dynamically)
    while IFS= read -r credfile; do
        [ -z "$credfile" ] && continue
        if [ "$os_type" = "Darwin" ]; then
            perms=$(stat -f "%OLp" "$credfile" 2>/dev/null || echo "000")
        else
            perms=$(stat -c "%a" "$credfile" 2>/dev/null || echo "000")
        fi
        local other_perms="${perms: -1}"
        if [ "$other_perms" -ge 4 ] 2>/dev/null; then
            add_finding "HIGH" "OC001" "Credential file permissions too open" \
                "Credential file has permissions ${perms}, may expose auth tokens" \
                "$credfile" \
                "Run: chmod 600 ${credfile}"
        fi
    done < <(find "$OPENCLAW_HOME_DIR" -name "creds.json" -type f 2>/dev/null || true)
}

# ============================================================
# CHECK 2: Gateway network binding
# ============================================================
check_gateway_binding() {
    config_file_exists || return

    local bind_match
    bind_match=$(config_grep '"bind"\s*:\s*"(lan|tailnet|0\.0\.0\.0)"' || true)
    if [ -n "$bind_match" ]; then
        local bind_type
        bind_type=$(echo "$bind_match" | grep -oE '(lan|tailnet|0\.0\.0\.0)' | head -1)
        local severity="HIGH"
        [ "$bind_type" = "tailnet" ] && severity="MEDIUM"

        add_finding "$severity" "OC002" "Gateway bound to non-loopback interface" \
            "Gateway bind is set to '${bind_type}', exposing Control UI and API beyond localhost" \
            "$CONFIG_FILE" \
            "Use 'loopback' binding unless remote access is explicitly needed. If LAN needed, ensure gateway.auth is set."
    fi

    # Check if gateway auth is configured when bound to non-loopback
    if [ -n "$bind_match" ]; then
        local has_auth
        has_auth=$(config_grep '"auth"\s*:\s*{' || true)
        if [ -z "$has_auth" ]; then
            add_finding "CRITICAL" "OC002" "Gateway exposed without authentication" \
                "Gateway is bound to non-loopback but no gateway.auth (token/password) is configured" \
                "$CONFIG_FILE" \
                "Set gateway.auth with a strong token or password: { auth: { token: 'strong-secret' } }"
        fi
    fi

    # Also check for weak/short auth tokens
    local auth_token
    auth_token=$(config_grep '"token"\s*:\s*"[^"]{1,7}"' || true)
    if [ -n "$auth_token" ] && [ -n "$bind_match" ]; then
        add_finding "HIGH" "OC002" "Gateway auth token appears weak/short" \
            "Auth token is less than 8 characters. Short tokens are vulnerable to brute force." \
            "$CONFIG_FILE" \
            "Use a token of at least 32 characters or a strong password"
    fi
}

# ============================================================
# CHECK 3: DM and Group access policies
# ============================================================
check_access_policies() {
    config_file_exists || return

    local dm_open
    dm_open=$(config_grep '"dmPolicy"\s*:\s*"open"' || true)
    if [ -n "$dm_open" ]; then
        add_finding "HIGH" "OC003" "DM policy set to 'open'" \
            "Anyone can send direct messages to the bot without authentication or pairing" \
            "$CONFIG_FILE" \
            "Use 'pairing' (default) or 'allowlist' dmPolicy to restrict access"
    fi

    local wildcard_allow
    wildcard_allow=$(config_grep '"allowFrom"\s*:\s*\[.*"\*"' || true)
    if [ -n "$wildcard_allow" ]; then
        add_finding "HIGH" "OC003" "allowFrom contains wildcard '*'" \
            "Access whitelist uses wildcard, allowing messages from any sender" \
            "$CONFIG_FILE" \
            "Restrict allowFrom to specific phone numbers or user IDs"
    fi

    local group_open
    group_open=$(config_grep '"groupPolicy"\s*:\s*"open"' || true)
    if [ -n "$group_open" ]; then
        add_finding "MEDIUM" "OC003" "Group policy set to 'open'" \
            "Any member in allowed groups can trigger the bot without sender restriction" \
            "$CONFIG_FILE" \
            "Use 'allowlist' groupPolicy with groupAllowFrom for sender-level control"
    fi

    local mention_disabled
    mention_disabled=$(config_grep '"requireMention"\s*:\s*false' || true)
    if [ -n "$mention_disabled" ]; then
        add_finding "MEDIUM" "OC003" "Group mention requirement disabled" \
            "Bot will respond to all group messages without requiring @mention" \
            "$CONFIG_FILE" \
            "Enable requireMention to prevent accidental trigger in noisy groups"
    fi
}

# ============================================================
# CHECK 4: Sandbox configuration
# ============================================================
check_sandbox_config() {
    config_file_exists || return

    local sandbox_off
    sandbox_off=$(config_grep '"mode"\s*:\s*"off"' || true)
    if [ -n "$sandbox_off" ]; then
        add_finding "HIGH" "OC004" "Sandbox mode is disabled" \
            "Agent sandbox is explicitly set to 'off', giving full host access" \
            "$CONFIG_FILE" \
            "Enable sandbox: mode 'non-main' or 'all' to isolate agent execution in Docker containers"
    fi

    local has_sandbox
    has_sandbox=$(config_grep '"sandbox"' || true)
    if [ -z "$has_sandbox" ]; then
        add_finding "MEDIUM" "OC004" "No sandbox configuration found" \
            "No explicit sandbox configuration detected. Default behavior depends on OpenClaw version." \
            "$CONFIG_FILE" \
            "Explicitly configure sandbox: { mode: 'non-main', backend: 'docker', scope: 'agent' }"
    fi

    local ws_rw
    ws_rw=$(config_grep '"workspaceAccess"\s*:\s*"rw"' || true)
    if [ -n "$ws_rw" ]; then
        add_finding "LOW" "OC004" "Sandbox has read-write workspace access" \
            "Sandboxed agents can modify workspace files" \
            "$CONFIG_FILE" \
            "Consider 'ro' (read-only) workspaceAccess unless write is required"
    fi

    local docker_network
    docker_network=$(config_grep '"network"\s*:\s*"(host|bridge)"' || true)
    if [ -n "$docker_network" ]; then
        add_finding "HIGH" "OC004" "Docker sandbox network not isolated" \
            "Sandbox Docker network is not 'none', agent may access external services" \
            "$CONFIG_FILE" \
            "Use network: 'none' to fully isolate sandbox network access"
    fi

    # Check for policy drift: sandbox Docker configured but mode is off
    if [ -n "$sandbox_off" ] && [ -n "$(config_grep '"backend"\s*:\s*"docker"' || true)" ]; then
        add_finding "MEDIUM" "OC004" "Policy drift: Docker sandbox configured but mode is off" \
            "Sandbox backend is set to 'docker' but mode is 'off', sandbox won't actually run" \
            "$CONFIG_FILE" \
            "Set sandbox.mode to 'non-main' or 'all' to activate Docker sandboxing"
    fi
}

# ============================================================
# CHECK 5: Tool permissions
# ============================================================
check_tool_permissions() {
    config_file_exists || return

    local elevated_enabled
    elevated_enabled=$(config_grep '"elevated"\s*:\s*{' || true)
    if [ -n "$elevated_enabled" ]; then
        local elev_on
        elev_on=$(config_grep '"elevated".*"enabled"\s*:\s*true' || true)
        if [ -n "$elev_on" ]; then
            add_finding "HIGH" "OC005" "Elevated (host exec) tools enabled" \
                "Agent can execute commands with elevated privileges on the host machine" \
                "$CONFIG_FILE" \
                "Disable elevated tools unless absolutely necessary. Restrict via allowFrom."
        fi
    fi

    local profile_full
    profile_full=$(config_grep '"profile"\s*:\s*"full"' || true)
    if [ -n "$profile_full" ]; then
        add_finding "MEDIUM" "OC005" "Tool profile set to 'full'" \
            "All tools are available to the agent including potentially dangerous ones" \
            "$CONFIG_FILE" \
            "Use 'coding' or 'minimal' profile and explicitly allow only needed tools"
    fi

    local has_deny
    has_deny=$(config_grep '"deny"\s*:' || true)
    if [ -z "$has_deny" ]; then
        add_finding "MEDIUM" "OC005" "No tool deny list configured" \
            "No tools are explicitly denied. Agent may access gateway config, cron, and session management tools." \
            "$CONFIG_FILE" \
            "Add deny list for control-plane tools: ['gateway', 'cron', 'sessions_spawn'] per OpenClaw security docs"
    fi
}

# ============================================================
# CHECK 6: Skill security
# ============================================================
check_skill_security() {
    config_file_exists || return

    # Check for hardcoded API keys in skill entries
    local skill_keys
    skill_keys=$(config_grep '"apiKey"\s*:\s*"[^{$]' || true)
    if [ -n "$skill_keys" ]; then
        local masked
        masked=$(echo "$skill_keys" | sed -E 's/"apiKey"\s*:\s*"([^"]{4})[^"]*"/"apiKey": "\1****REDACTED****"/g')
        add_finding "HIGH" "OC006" "Skill API key hardcoded in config" \
            "Found inline API key in skill entry: ${masked}" \
            "$CONFIG_FILE" \
            "Use SecretRef ({ source: 'env', id: 'VAR_NAME' }) instead of inline API keys"
    fi

    # Search for third-party skills dynamically within the state directory
    if [ -d "$OPENCLAW_HOME_DIR" ]; then
        local skills_dirs=()
        while IFS= read -r sdir; do
            [ -n "$sdir" ] && skills_dirs+=("$sdir")
        done < <(find "$OPENCLAW_HOME_DIR" -maxdepth 2 -name "skills" -type d 2>/dev/null || true)

        for skills_dir in "${skills_dirs[@]}"; do
            local skill_count
            skill_count=$(find "$skills_dir" -name "SKILL.md" -maxdepth 2 2>/dev/null | wc -l | tr -d ' ')
            if [ "$skill_count" -gt 0 ]; then
                add_finding "INFO" "OC006" "Third-party skills installed (${skill_count})" \
                    "Found ${skill_count} skill(s) in ${skills_dir}. Third-party skills should be treated as untrusted code." \
                    "$skills_dir" \
                    "Review each skill's SKILL.md before use. Consider running untrusted skills in sandbox mode."
            fi
        done
    fi

    local allow_bundled
    allow_bundled=$(config_grep '"allowBundled"' || true)
    if [ -z "$allow_bundled" ]; then
        add_finding "INFO" "OC006" "No skill allowlist configured" \
            "All bundled skills are loaded by default. Consider restricting to only needed skills." \
            "${CONFIG_FILE:-state_dir}" \
            "Set skills.allowBundled to limit which bundled skills are active"
    fi
}

# ============================================================
# CHECK 7: Webhook/Hooks security
# ============================================================
check_hooks_security() {
    config_file_exists || return

    local hooks_enabled
    hooks_enabled=$(config_grep '"hooks".*"enabled"\s*:\s*true' || true)
    if [ -z "$hooks_enabled" ]; then
        return
    fi

    local token_set
    token_set=$(config_grep '"token"\s*:\s*"[^"]+' || true)
    if [ -n "$hooks_enabled" ] && [ -z "$token_set" ]; then
        add_finding "CRITICAL" "OC007" "Webhook hooks enabled without shared secret" \
            "Hooks are enabled but no token is configured. Anyone can trigger agent actions." \
            "$CONFIG_FILE" \
            "Set hooks.token to a strong shared secret for webhook authentication"
    fi

    local unsafe_content
    unsafe_content=$(config_grep '"allowUnsafeExternalContent"\s*:\s*true' || true)
    if [ -n "$unsafe_content" ]; then
        add_finding "HIGH" "OC007" "Unsafe external content allowed in hooks" \
            "allowUnsafeExternalContent is true, webhook payloads are not sanitized" \
            "$CONFIG_FILE" \
            "Disable allowUnsafeExternalContent unless actively debugging"
    fi
}

# ============================================================
# CHECK 8: Cron job security
# ============================================================
check_cron_security() {
    config_file_exists || return

    local cron_enabled
    cron_enabled=$(config_grep '"cron".*"enabled"\s*:\s*true' || true)
    if [ -z "$cron_enabled" ]; then
        return
    fi

    local cron_denied
    cron_denied=$(config_grep '"deny".*"cron"' || true)
    if [ -z "$cron_denied" ]; then
        add_finding "MEDIUM" "OC008" "Cron tool not in deny list" \
            "Cron is enabled and the cron tool is accessible, allowing agents to create scheduled tasks" \
            "$CONFIG_FILE" \
            "Add 'cron' to tools.deny if agents should not create their own scheduled tasks"
    fi
}

# ============================================================
# CHECK 9: Logging and redaction
# ============================================================
check_logging_config() {
    config_file_exists || return

    local redact_on
    redact_on=$(config_grep '"redactSensitive"\s*:\s*true' || true)
    local redact_off
    redact_off=$(config_grep '"redactSensitive"\s*:\s*false' || true)

    if [ -n "$redact_off" ]; then
        add_finding "HIGH" "OC009" "Sensitive log redaction disabled" \
            "logging.redactSensitive is explicitly set to false, secrets may leak to logs" \
            "$CONFIG_FILE" \
            "Enable logging.redactSensitive: true to prevent secret leakage"
    elif [ -z "$redact_on" ]; then
        add_finding "LOW" "OC009" "Sensitive log redaction not explicitly enabled" \
            "Consider explicitly enabling logging.redactSensitive for defense in depth" \
            "$CONFIG_FILE" \
            "Set logging.redactSensitive: true in your configuration"
    fi
}

# ============================================================
# CHECK 10: mDNS / Bonjour exposure
# ============================================================
check_mdns_config() {
    config_file_exists || return

    local mdns_full
    mdns_full=$(config_grep '"mdns".*"mode"\s*:\s*"full"' || true)
    if [ -z "$mdns_full" ]; then
        mdns_full=$(config_grep '"mode"\s*:\s*"full"' || true)
        # Only match if it's within a discovery/mdns context
        if [ -n "$mdns_full" ]; then
            local mdns_context
            mdns_context=$(config_grep '"discovery"' || true)
            [ -z "$mdns_context" ] && mdns_full=""
        fi
    fi

    if [ -n "$mdns_full" ]; then
        add_finding "MEDIUM" "OC010" "mDNS set to 'full' broadcast mode" \
            "mDNS in full mode broadcasts cliPath, sshPort, and other internal info to LAN" \
            "$CONFIG_FILE" \
            "Set mdns mode to 'minimal' or 'off' to reduce information exposure. Or set OPENCLAW_DISABLE_BONJOUR=1"
    fi
}

# ============================================================
# CHECK 11: Multi-agent isolation
# ============================================================
check_multi_agent() {
    config_file_exists || return

    # Check if multiple agents share agentDir
    local agent_dirs=()
    while IFS= read -r dir_match; do
        [ -z "$dir_match" ] && continue
        local dir_val
        dir_val=$(echo "$dir_match" | grep -oE '"[^"]*"' | tail -1 | tr -d '"')
        [ -n "$dir_val" ] && agent_dirs+=("$dir_val")
    done < <(config_grep '"agentDir"\s*:' || true)

    if [ "${#agent_dirs[@]}" -gt 1 ]; then
        local unique_dirs
        unique_dirs=$(printf '%s\n' "${agent_dirs[@]}" | sort -u | wc -l | tr -d ' ')
        if [ "$unique_dirs" -lt "${#agent_dirs[@]}" ]; then
            add_finding "CRITICAL" "OC011" "Multiple agents sharing agentDir" \
                "Different agents share the same agentDir, causing auth and session conflicts" \
                "$CONFIG_FILE" \
                "Each agent must have a unique agentDir to prevent credential and session cross-contamination"
        fi
    fi

    local workspace_count
    workspace_count=$(config_grep '"workspace"\s*:' | wc -l | tr -d ' ')
    local agent_count
    agent_count=$(config_grep '"id"\s*:' | wc -l | tr -d ' ')

    if [ "$agent_count" -gt 1 ] && [ "$workspace_count" -lt "$agent_count" ]; then
        add_finding "MEDIUM" "OC011" "Multiple agents may share default workspace" \
            "Found ${agent_count} agents but fewer explicit workspace paths" \
            "$CONFIG_FILE" \
            "Assign each agent a unique workspace path for proper isolation"
    fi
}

# ============================================================
# CHECK 12: Session data security
# ============================================================
check_session_security() {
    [ -d "$OPENCLAW_HOME_DIR" ] || return

    local os_type
    os_type=$(uname -s)

    # Dynamically find all session directories (don't assume path structure)
    while IFS= read -r session_dir; do
        [ -z "$session_dir" ] && continue
        local perms
        if [ "$os_type" = "Darwin" ]; then
            perms=$(stat -f "%OLp" "$session_dir" 2>/dev/null || echo "000")
        else
            perms=$(stat -c "%a" "$session_dir" 2>/dev/null || echo "000")
        fi
        local other_perms="${perms: -1}"
        if [ "$other_perms" -ge 4 ] 2>/dev/null; then
            add_finding "HIGH" "OC012" "Session storage accessible by others" \
                "Session directory has permissions ${perms}, conversation history may be exposed" \
                "$session_dir" \
                "Run: chmod 700 ${session_dir}"
        fi
    done < <(find "$OPENCLAW_HOME_DIR" -maxdepth 5 -name "sessions" -type d 2>/dev/null || true)

    # Check JSONL session files directly
    while IFS= read -r session_file; do
        [ -z "$session_file" ] && continue
        local perms
        if [ "$os_type" = "Darwin" ]; then
            perms=$(stat -f "%OLp" "$session_file" 2>/dev/null || echo "000")
        else
            perms=$(stat -c "%a" "$session_file" 2>/dev/null || echo "000")
        fi
        local other_perms="${perms: -1}"
        if [ "$other_perms" -ge 4 ] 2>/dev/null; then
            add_finding "MEDIUM" "OC012" "Session file readable by others" \
                "Session JSONL file has permissions ${perms}, may contain sensitive conversation data" \
                "$session_file" \
                "Run: chmod 600 ${session_file}"
        fi
    done < <(find "$OPENCLAW_HOME_DIR" -maxdepth 6 -name "*.jsonl" -path "*/sessions/*" -type f 2>/dev/null | head -20 || true)
}

# ============================================================
# CHECK 13: SSRF browser policy
# ============================================================
check_browser_ssrf() {
    config_file_exists || return

    local ssrf_allow
    ssrf_allow=$(config_grep '"dangerouslyAllowPrivateNetwork"\s*:\s*true' || true)
    if [ -n "$ssrf_allow" ]; then
        add_finding "MEDIUM" "OC013" "Browser SSRF private network access allowed" \
            "dangerouslyAllowPrivateNetwork is true, agent browser can access internal services" \
            "$CONFIG_FILE" \
            "Set to false and use hostnameAllowlist for specific internal services if needed"
    fi
}

# ============================================================
# CHECK 14: Plugin hook prompt injection
# ============================================================
check_plugin_security() {
    config_file_exists || return

    local prompt_inject
    prompt_inject=$(config_grep '"allowPromptInjection"\s*:\s*true' || true)
    if [ -n "$prompt_inject" ]; then
        add_finding "HIGH" "OC014" "Plugin prompt injection allowed" \
            "A plugin is allowed to modify agent system prompts, which can alter agent behavior" \
            "$CONFIG_FILE" \
            "Disable hooks.allowPromptInjection unless the plugin is fully trusted"
    fi

    # Check for plugins/extensions without allowlist
    if [ -d "$OPENCLAW_HOME_DIR" ]; then
        local ext_dirs=()
        while IFS= read -r edir; do
            [ -n "$edir" ] && ext_dirs+=("$edir")
        done < <(find "$OPENCLAW_HOME_DIR" -maxdepth 2 -name "extensions" -type d 2>/dev/null || true)

        for ext_dir in "${ext_dirs[@]}"; do
            local ext_count
            ext_count=$(find "$ext_dir" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')
            if [ "$ext_count" -gt 0 ]; then
                local has_allowlist
                has_allowlist=$(config_grep '"plugins".*"allow"' || true)
                if [ -z "$has_allowlist" ]; then
                    add_finding "MEDIUM" "OC014" "Plugins installed without allowlist (${ext_count} found)" \
                        "Found ${ext_count} plugin(s) in ${ext_dir} but no explicit plugin allowlist configured" \
                        "$ext_dir" \
                        "Configure plugins.allow to restrict which plugins can be loaded"
                fi
            fi
        done
    fi
}

# ============================================================
# CHECK 15: .env files within OpenClaw state directory
# ============================================================
check_openclaw_env_files() {
    [ -d "$OPENCLAW_HOME_DIR" ] || return

    # Check for .env files that may contain sensitive data
    while IFS= read -r envfile; do
        [ -z "$envfile" ] && continue
        local os_type perms
        os_type=$(uname -s)
        if [ "$os_type" = "Darwin" ]; then
            perms=$(stat -f "%OLp" "$envfile" 2>/dev/null || echo "000")
        else
            perms=$(stat -c "%a" "$envfile" 2>/dev/null || echo "000")
        fi
        local other_perms="${perms: -1}"
        if [ "$other_perms" -ge 4 ] 2>/dev/null; then
            add_finding "HIGH" "OC015" "OpenClaw .env file readable by others" \
                ".env file has permissions ${perms}, may expose API keys and secrets" \
                "$envfile" \
                "Run: chmod 600 ${envfile}"
        fi
    done < <(find "$OPENCLAW_HOME_DIR" -name ".env" -o -name ".env.*" -type f 2>/dev/null || true)
}

# ============================================================
# Main
# ============================================================
emit_header "openclaw" "${1:-auto-discover}"

# Phase 1: Discovery
find_openclaw_cli || true
discover_state_dir "${1:-}" || true
discover_config_file || true

# Phase 2: Report discovery results
if ! emit_discovery_report; then
    emit_footer "openclaw"
    exit 0
fi

# Phase 3: Run all checks
check_home_permissions
check_gateway_binding
check_access_policies
check_sandbox_config
check_tool_permissions
check_skill_security
check_hooks_security
check_cron_security
check_logging_config
check_mdns_config
check_multi_agent
check_session_security
check_browser_ssrf
check_plugin_security
check_openclaw_env_files

emit_footer "openclaw"
