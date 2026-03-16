#!/usr/bin/env bash
# ClawSafe - File System Security Check
# Supports: Linux, macOS, containers
# Usage: bash check_files.sh [target_directory]
# Output: JSON lines, one finding per line

set -euo pipefail

TARGET_DIR="${1:-.}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/utils.sh"

# ============================================================
# CHECK 1: Agent can read sensitive system files
# ============================================================
check_sensitive_file_access() {
    local home_dir="${HOME:-/root}"

    local sensitive_files=(
        "/etc/passwd"
        "/etc/shadow"
        "/etc/sudoers"
        "${home_dir}/.ssh/id_rsa"
        "${home_dir}/.ssh/id_ed25519"
        "${home_dir}/.ssh/config"
        "${home_dir}/.aws/credentials"
        "${home_dir}/.aws/config"
        "${home_dir}/.kube/config"
        "${home_dir}/.docker/config.json"
        "${home_dir}/.npmrc"
        "${home_dir}/.pypirc"
        "${home_dir}/.netrc"
        "${home_dir}/.bash_history"
        "${home_dir}/.zsh_history"
        "${home_dir}/.gnupg/secring.gpg"
        "${home_dir}/.azure/accessTokens.json"
        "${home_dir}/.gcloud/credentials.db"
    )

    for filepath in "${sensitive_files[@]}"; do
        if [ -r "$filepath" ] 2>/dev/null; then
            local severity="HIGH"
            case "$filepath" in
                */shadow|*id_rsa|*id_ed25519|*/credentials|*/secring*|*/accessTokens*)
                    severity="CRITICAL" ;;
                *history|*/config)
                    severity="MEDIUM" ;;
            esac
            add_finding "$severity" "FS001" "Agent can read sensitive file" \
                "The current process has read access to ${filepath}" \
                "$filepath" \
                "Restrict file permissions or run Agent in a sandboxed environment"
        fi
    done
}

# ============================================================
# CHECK 2: Agent has write access to system directories
# ============================================================
check_system_write_access() {
    local system_dirs=("/etc" "/usr/bin" "/usr/local/bin" "/var/log" "/tmp" "/var/tmp")

    for dir in "${system_dirs[@]}"; do
        if [ -d "$dir" ] && [ -w "$dir" ] 2>/dev/null; then
            local severity="HIGH"
            case "$dir" in
                /tmp|/var/tmp) severity="LOW" ;;
                /etc|/usr/bin|/usr/local/bin) severity="CRITICAL" ;;
            esac
            add_finding "$severity" "FS002" "Agent has write access to system directory" \
                "The current process can write to ${dir}" \
                "$dir" \
                "Run Agent with reduced privileges or in a read-only container filesystem"
        fi
    done
}

# ============================================================
# CHECK 3: Log files containing sensitive information
# ============================================================
check_log_sensitive_info() {
    local log_patterns=(
        'password\s*[:=]\s*\S+'
        'api[_-]?key\s*[:=]\s*\S+'
        'secret\s*[:=]\s*\S+'
        'token\s*[:=]\s*\S+'
        'Authorization:\s*Bearer\s+\S+'
        'X-API-Key:\s*\S+'
        'sk-[A-Za-z0-9]{20,}'
        'sk-ant-[A-Za-z0-9]{20,}'
    )

    while IFS= read -r logfile; do
        [ -z "$logfile" ] && continue
        for pattern in "${log_patterns[@]}"; do
            local match_count
            match_count=$(tail -1000 "$logfile" 2>/dev/null | grep -ciE "$pattern" 2>/dev/null || echo "0")
            if [ "$match_count" -gt 0 ]; then
                add_finding "HIGH" "FS003" "Log file may contain sensitive data" \
                    "Found ${match_count} potential sensitive data pattern(s) in log file" \
                    "$logfile" \
                    "Configure logging to redact sensitive fields; rotate and encrypt logs"
                break
            fi
        done
    done < <(find "$TARGET_DIR" \( -name "*.log" -o -name "*.log.*" -o -path "*/logs/*" \) \
        -type f -not -path "*/.git/*" 2>/dev/null || true)
}

# ============================================================
# CHECK 4: Temp files with sensitive data residue
# ============================================================
check_temp_file_residue() {
    local temp_dirs=("/tmp" "/var/tmp" "${TMPDIR:-/tmp}")
    local current_user
    current_user=$(whoami 2>/dev/null || echo "unknown")

    for tmp_dir in "${temp_dirs[@]}"; do
        [ -d "$tmp_dir" ] || continue
        while IFS= read -r tmpfile; do
            [ -z "$tmpfile" ] && continue
            if head -c 4096 "$tmpfile" 2>/dev/null | grep -qiE '(api.?key|secret|password|token|credential|private.?key)' 2>/dev/null; then
                add_finding "MEDIUM" "FS004" "Temp file may contain sensitive data" \
                    "Temporary file owned by current user may contain sensitive patterns" \
                    "$tmpfile" \
                    "Ensure temporary files are securely deleted after use"
            fi
        done < <(find "$tmp_dir" -maxdepth 2 -user "$current_user" -type f -mmin -1440 2>/dev/null || true)
    done
}

# ============================================================
# CHECK 5: Sensitive key/cert files in project directory
# ============================================================
check_sensitive_files_in_project() {
    local sensitive_extensions=("pem" "key" "p12" "pfx" "jks" "keystore")

    for ext in "${sensitive_extensions[@]}"; do
        while IFS= read -r file; do
            [ -z "$file" ] && continue
            add_finding "HIGH" "FS005" "Sensitive file found in project" \
                "A file with sensitive extension .${ext} was found in the project" \
                "$file" \
                "Remove key/certificate files from the project; use a secret manager or runtime mount"
        done < <(find "$TARGET_DIR" -name "*.${ext}" -not -path "*/.git/*" -not -path "*/node_modules/*" 2>/dev/null || true)
    done
}

# ============================================================
# Main
# ============================================================
emit_header "filesystem" "$TARGET_DIR"

check_sensitive_file_access
check_system_write_access
check_log_sensitive_info
check_temp_file_residue
check_sensitive_files_in_project

emit_footer "filesystem"
