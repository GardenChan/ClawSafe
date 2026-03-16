#!/usr/bin/env bash
# ClawSafe - Environment Configuration Security Check
# Supports: Linux, macOS, containers
# Usage: bash check_env.sh [target_directory]
# Output: JSON lines, one finding per line

set -euo pipefail

TARGET_DIR="${1:-.}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/utils.sh"

# ============================================================
# CHECK 1: API Key / Secret hardcoded in config files
# ============================================================
check_hardcoded_secrets() {
    local patterns=(
        'api[_-]?key\s*[:=]\s*["'"'"'][A-Za-z0-9_\-]{16,}'
        'secret[_-]?key\s*[:=]\s*["'"'"'][A-Za-z0-9_\-]{16,}'
        'password\s*[:=]\s*["'"'"'][^\s"'"'"']{8,}'
        'token\s*[:=]\s*["'"'"'][A-Za-z0-9_\-\.]{16,}'
        'OPENAI_API_KEY\s*[:=]\s*["'"'"']sk-[A-Za-z0-9]{20,}'
        'ANTHROPIC_API_KEY\s*[:=]\s*["'"'"']sk-ant-[A-Za-z0-9]{20,}'
        'AWS_SECRET_ACCESS_KEY\s*[:=]\s*["'"'"'][A-Za-z0-9/+=]{30,}'
    )
    local config_extensions=("yaml" "yml" "json" "toml" "ini" "cfg" "conf" "py" "js" "ts")

    for ext in "${config_extensions[@]}"; do
        while IFS= read -r file; do
            [ -z "$file" ] && continue
            for pattern in "${patterns[@]}"; do
                while IFS= read -r match; do
                    [ -z "$match" ] && continue
                    local line_num
                    line_num=$(echo "$match" | cut -d: -f1)
                    # Mask the secret value - only show first 4 chars
                    local masked
                    masked=$(echo "$match" | sed -E "s/([\"'])[A-Za-z0-9_.\/+=\-]{4}[A-Za-z0-9_.\/+=\-]*/\1****REDACTED****/g")
                    add_finding "HIGH" "ENV001" "Potential hardcoded secret detected" \
                        "Found pattern matching hardcoded credential: ${masked}" \
                        "${file}:${line_num}" \
                        "Use environment variables or a secret manager instead of hardcoding secrets"
                done < <(grep -inE "$pattern" "$file" 2>/dev/null || true)
            done
        done < <(find "$TARGET_DIR" -name "*.${ext}" \
            -not -path "*/node_modules/*" -not -path "*/.git/*" \
            -not -path "*/venv/*" -not -path "*/__pycache__/*" \
            -not -path "*/.venv/*" -not -path "*/env/*" 2>/dev/null || true)
    done
}

# ============================================================
# CHECK 2: .env file tracked by git
# ============================================================
check_env_git_tracked() {
    if ! git -C "$TARGET_DIR" rev-parse --is-inside-work-tree &>/dev/null; then
        add_finding "INFO" "ENV002" "Not a git repository" \
            "Target directory is not inside a git repository, skipping .env git tracking check" \
            "$TARGET_DIR" \
            "No action needed"
        return
    fi

    while IFS= read -r envfile; do
        [ -z "$envfile" ] && continue
        if git -C "$TARGET_DIR" ls-files --error-unmatch "$envfile" &>/dev/null; then
            add_finding "CRITICAL" "ENV002" ".env file tracked by git" \
                "The file ${envfile} is tracked by git and may contain secrets" \
                "$envfile" \
                "Add .env to .gitignore and remove from tracking: git rm --cached ${envfile}"
        fi
    done < <(find "$TARGET_DIR" \( -name ".env" -o -name ".env.*" \) \
        -not -name ".env.example" -not -name ".env.template" -not -name ".env.sample" \
        2>/dev/null || true)

    local gitignore="${TARGET_DIR}/.gitignore"
    if [ -f "$gitignore" ]; then
        if ! grep -qE '^\s*\.env\s*$|^\s*\.env\.\*\s*$' "$gitignore" 2>/dev/null; then
            add_finding "MEDIUM" "ENV003" ".env not in .gitignore" \
                ".gitignore exists but does not contain a .env exclusion pattern" \
                "$gitignore" \
                "Add '.env' and '.env.*' to .gitignore"
        fi
    else
        add_finding "LOW" "ENV003" "No .gitignore found" \
            "No .gitignore file found in the project root" \
            "$TARGET_DIR" \
            "Create a .gitignore file with .env patterns"
    fi
}

# ============================================================
# CHECK 3: Config file permissions too open
# ============================================================
check_file_permissions() {
    local sensitive_extensions=("yaml" "yml" "json" "toml" "ini" "cfg" "conf" "pem" "key" "p12" "pfx")
    local sensitive_names=(".env" "secret" "credential" "password" "token")

    local os_type
    os_type=$(uname -s)

    local all_files=()
    for ext in "${sensitive_extensions[@]}"; do
        while IFS= read -r f; do
            [ -n "$f" ] && all_files+=("$f")
        done < <(find "$TARGET_DIR" -name "*.${ext}" -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null || true)
    done
    for pat in "${sensitive_names[@]}"; do
        while IFS= read -r f; do
            [ -n "$f" ] && all_files+=("$f")
        done < <(find "$TARGET_DIR" -iname "*${pat}*" -type f -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null || true)
    done

    for file in "${all_files[@]}"; do
        local perms
        if [ "$os_type" = "Darwin" ]; then
            perms=$(stat -f "%OLp" "$file" 2>/dev/null || echo "000")
        else
            perms=$(stat -c "%a" "$file" 2>/dev/null || echo "000")
        fi

        local other_perms="${perms: -1}"
        if [ "$other_perms" -ge 6 ] 2>/dev/null; then
            add_finding "HIGH" "ENV004" "Sensitive config file world-writable" \
                "File has permissions ${perms}, allowing other users to modify it" \
                "$file" \
                "Restrict permissions: chmod 600 ${file}"
        elif [ "$other_perms" -ge 4 ] 2>/dev/null; then
            add_finding "MEDIUM" "ENV004" "Sensitive config file world-readable" \
                "File has permissions ${perms}, allowing other users to read it" \
                "$file" \
                "Restrict permissions: chmod 600 ${file}"
        fi
    done
}

# ============================================================
# CHECK 4: Default/placeholder values still in config
# ============================================================
check_default_values() {
    local default_patterns=(
        'changeme' 'CHANGEME' 'your[_-]?api[_-]?key' 'your[_-]?secret'
        'TODO:?\s*replace' 'REPLACE[_-]?ME' 'placeholder'
        'default[_-]?password' 'admin:admin' 'root:root'
    )
    local config_extensions=("yaml" "yml" "json" "toml" "ini" "cfg" "conf" "env")

    for ext in "${config_extensions[@]}"; do
        while IFS= read -r file; do
            [ -z "$file" ] && continue
            for pattern in "${default_patterns[@]}"; do
                while IFS= read -r match; do
                    [ -z "$match" ] && continue
                    local line_num
                    line_num=$(echo "$match" | cut -d: -f1)
                    local line_content
                    line_content=$(echo "$match" | cut -d: -f2-)
                    add_finding "MEDIUM" "ENV005" "Default/placeholder value in config" \
                        "Found potential default value: $(echo "$line_content" | head -c 80)" \
                        "${file}:${line_num}" \
                        "Replace default/placeholder values with actual configuration"
                done < <(grep -inE "$pattern" "$file" 2>/dev/null || true)
            done
        done < <(find "$TARGET_DIR" -name "*.${ext}" -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null || true)
    done
}

# ============================================================
# Main
# ============================================================
emit_header "environment" "$TARGET_DIR"

check_hardcoded_secrets
check_env_git_tracked
check_file_permissions
check_default_values

emit_footer "environment"
