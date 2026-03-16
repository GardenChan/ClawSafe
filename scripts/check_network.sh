#!/usr/bin/env bash
# ClawSafe - Network Exposure Security Check
# Supports: Linux, macOS, containers
# Usage: bash check_network.sh [target_directory]
# Output: JSON lines, one finding per line

set -euo pipefail

TARGET_DIR="${1:-.}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/utils.sh"

# ============================================================
# CHECK 1: Listening ports bound to 0.0.0.0 (all interfaces)
# ============================================================
check_listening_ports() {
    local os_type
    os_type=$(uname -s)

    if [ "$os_type" = "Darwin" ]; then
        local port_info
        port_info=$(lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null || true)
        if [ -z "$port_info" ]; then
            add_finding "INFO" "NET001" "No listening ports detected" \
                "No TCP listening ports found (or insufficient permissions)" \
                "system" \
                "Run with appropriate permissions to inspect network state"
            return
        fi
        echo "$port_info" | grep -E '\*:' | while IFS= read -r line; do
            [ -z "$line" ] && continue
            local proc_name port_num
            proc_name=$(echo "$line" | awk '{print $1}')
            port_num=$(echo "$line" | grep -oE '\*:[0-9]+' | cut -d: -f2 | head -1)
            [ -z "$port_num" ] && continue
            add_finding "MEDIUM" "NET001" "Service bound to all interfaces" \
                "Process '${proc_name}' is listening on *:${port_num}" \
                "0.0.0.0:${port_num}" \
                "Bind to 127.0.0.1:${port_num} to limit exposure to localhost"
        done
    else
        # Linux: prefer ss, fallback to netstat
        local port_info=""
        if command -v ss &>/dev/null; then
            port_info=$(ss -tlnp 2>/dev/null || true)
        elif command -v netstat &>/dev/null; then
            port_info=$(netstat -tlnp 2>/dev/null || true)
        else
            add_finding "INFO" "NET001" "Cannot detect listening ports" \
                "Neither ss nor netstat is available" \
                "system" \
                "Install iproute2 or net-tools for network inspection"
            return
        fi
        echo "$port_info" | grep -E '0\.0\.0\.0:' | while IFS= read -r line; do
            [ -z "$line" ] && continue
            local addr_port
            addr_port=$(echo "$line" | grep -oE '0\.0\.0\.0:[0-9]+' | head -1)
            local port_num="${addr_port##*:}"
            add_finding "MEDIUM" "NET001" "Service bound to all interfaces" \
                "A service is listening on ${addr_port} (all interfaces)" \
                "${addr_port}" \
                "Bind to 127.0.0.1:${port_num} to limit exposure to localhost"
        done
    fi
}

# ============================================================
# CHECK 2: HTTPS not enabled / SSL disabled
# ============================================================
check_https_config() {
    local config_extensions=("yaml" "yml" "json" "toml" "ini" "cfg" "conf" "py" "js" "ts" "env")

    for ext in "${config_extensions[@]}"; do
        while IFS= read -r file; do
            [ -z "$file" ] && continue

            # Check for non-localhost http:// URLs
            while IFS= read -r match; do
                [ -z "$match" ] && continue
                local line_num content
                line_num=$(echo "$match" | cut -d: -f1)
                content=$(echo "$match" | cut -d: -f2- | head -c 120)
                # Skip safe http URLs
                echo "$content" | grep -qiE 'http://(localhost|127\.0\.0\.1|0\.0\.0\.0|example\.com|\$|{|<)' && continue
                echo "$content" | grep -qiE '"\$schema"' && continue
                add_finding "MEDIUM" "NET002" "Non-HTTPS URL in configuration" \
                    "Found plain HTTP URL: $(echo "$content" | head -c 80)" \
                    "${file}:${line_num}" \
                    "Use HTTPS to encrypt data in transit"
            done < <(grep -nE 'http://[a-zA-Z0-9]' "$file" 2>/dev/null || true)

            # Check SSL/TLS explicitly disabled
            while IFS= read -r match; do
                [ -z "$match" ] && continue
                local line_num
                line_num=$(echo "$match" | cut -d: -f1)
                add_finding "HIGH" "NET002" "SSL/TLS appears disabled" \
                    "Configuration suggests SSL/TLS is explicitly disabled" \
                    "${file}:${line_num}" \
                    "Enable SSL/TLS for production deployments"
            done < <(grep -niE '(ssl|tls)\s*[:=]\s*(false|off|disabled|0)|verify_ssl\s*[:=]\s*(false|0)' "$file" 2>/dev/null || true)

        done < <(find "$TARGET_DIR" -name "*.${ext}" -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null || true)
    done
}

# ============================================================
# CHECK 3: CORS too permissive
# ============================================================
check_cors_config() {
    local code_extensions=("py" "js" "ts" "yaml" "yml" "json" "conf" "go" "java" "rb")

    for ext in "${code_extensions[@]}"; do
        while IFS= read -r file; do
            [ -z "$file" ] && continue

            # Wildcard CORS origin
            while IFS= read -r match; do
                [ -z "$match" ] && continue
                local line_num
                line_num=$(echo "$match" | cut -d: -f1)
                add_finding "HIGH" "NET003" "CORS allows all origins" \
                    "Wildcard '*' in CORS configuration allows any website to make requests" \
                    "${file}:${line_num}" \
                    "Restrict CORS to specific trusted origins"
            done < <(grep -nE "(allow_origins|Access-Control-Allow-Origin|cors.*origin|CORS_ORIGIN)\s*[:=]\s*[\"'\[]?\s*\*" "$file" 2>/dev/null || true)

        done < <(find "$TARGET_DIR" -name "*.${ext}" -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null || true)
    done
}

# ============================================================
# CHECK 4: Public IP in config
# ============================================================
check_public_ip_exposure() {
    local config_extensions=("yaml" "yml" "json" "toml" "ini" "cfg" "conf" "env")

    for ext in "${config_extensions[@]}"; do
        while IFS= read -r file; do
            [ -z "$file" ] && continue
            while IFS= read -r match; do
                [ -z "$match" ] && continue
                local line_num ip_addr
                line_num=$(echo "$match" | cut -d: -f1)
                ip_addr=$(echo "$match" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | head -1)
                # Filter private/loopback/link-local
                echo "$ip_addr" | grep -qE '^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.|0\.|255\.|169\.254\.)' && continue
                [ "$ip_addr" = "0.0.0.0" ] && continue
                add_finding "MEDIUM" "NET005" "Public IP address in config" \
                    "Config contains public IP: ${ip_addr}" \
                    "${file}:${line_num}" \
                    "Use DNS names or environment variables instead of hardcoded IPs"
            done < <(grep -nE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "$file" 2>/dev/null || true)
        done < <(find "$TARGET_DIR" -name "*.${ext}" -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null || true)
    done
}

# ============================================================
# Main
# ============================================================
emit_header "network" "$TARGET_DIR"

check_listening_ports
check_https_config
check_cors_config
check_public_ip_exposure

emit_footer "network"
