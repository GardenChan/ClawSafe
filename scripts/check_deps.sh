#!/usr/bin/env bash
# ClawSafe - Dependency Security Check
# Supports: Linux, macOS, containers
# Usage: bash check_deps.sh [target_directory]
# Output: JSON lines, one finding per line

set -euo pipefail

TARGET_DIR="${1:-.}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
source "${SCRIPT_DIR}/utils.sh"

# ============================================================
# CHECK 1: Python dependency version pinning
# ============================================================
check_python_deps() {
    while IFS= read -r reqfile; do
        [ -z "$reqfile" ] && continue

        local unpinned_count=0
        while IFS= read -r line; do
            echo "$line" | grep -qE '^\s*#|^\s*$|^\s*-' && continue
            if ! echo "$line" | grep -qE '(==|>=|<=|~=|!=|>|<)'; then
                unpinned_count=$((unpinned_count + 1))
            fi
        done < "$reqfile"

        if [ "$unpinned_count" -gt 0 ]; then
            add_finding "MEDIUM" "DEP001" "Unpinned Python dependencies" \
                "Found ${unpinned_count} dependencies without version pinning" \
                "$reqfile" \
                "Pin dependency versions (e.g., package==1.2.3) for reproducible builds"
        fi
    done < <(find "$TARGET_DIR" -name "requirements*.txt" -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null || true)

    # Check for lock file existence
    if [ -f "${TARGET_DIR}/pyproject.toml" ] || [ -f "${TARGET_DIR}/setup.py" ]; then
        if [ ! -f "${TARGET_DIR}/poetry.lock" ] && [ ! -f "${TARGET_DIR}/Pipfile.lock" ] && [ ! -f "${TARGET_DIR}/pdm.lock" ] && [ ! -f "${TARGET_DIR}/uv.lock" ]; then
            add_finding "MEDIUM" "DEP002" "No Python lock file found" \
                "Project has Python config but no dependency lock file" \
                "$TARGET_DIR" \
                "Use a lock file (poetry.lock, Pipfile.lock, uv.lock) to pin transitive dependencies"
        fi
    fi
}

# ============================================================
# CHECK 2: Node.js dependency version pinning
# ============================================================
check_node_deps() {
    while IFS= read -r pkgjson; do
        [ -z "$pkgjson" ] && continue
        local pkg_dir
        pkg_dir=$(dirname "$pkgjson")

        # Check for lock file
        if [ ! -f "${pkg_dir}/package-lock.json" ] && [ ! -f "${pkg_dir}/yarn.lock" ] && [ ! -f "${pkg_dir}/pnpm-lock.yaml" ]; then
            add_finding "MEDIUM" "DEP002" "No Node.js lock file found" \
                "package.json exists without a lock file" \
                "$pkgjson" \
                "Run npm install / yarn / pnpm install to generate a lock file"
        fi
    done < <(find "$TARGET_DIR" -name "package.json" -maxdepth 3 \
        -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null || true)
}

# ============================================================
# CHECK 3: Go dependency management
# ============================================================
check_go_deps() {
    if [ -f "${TARGET_DIR}/go.mod" ]; then
        if [ ! -f "${TARGET_DIR}/go.sum" ]; then
            add_finding "MEDIUM" "DEP002" "No go.sum file found" \
                "go.mod exists without go.sum for dependency verification" \
                "${TARGET_DIR}/go.mod" \
                "Run 'go mod tidy' to generate go.sum"
        fi
    fi
}

# ============================================================
# CHECK 4: Known vulnerability audit tools
# ============================================================
check_vulnerability_audit() {
    local found_audit=false

    # Python: pip-audit / safety
    if command -v pip-audit &>/dev/null; then
        local audit_output
        audit_output=$(cd "$TARGET_DIR" && pip-audit --format=json 2>/dev/null || true)
        if [ -n "$audit_output" ] && echo "$audit_output" | grep -q '"vulns"'; then
            local vuln_count
            vuln_count=$(echo "$audit_output" | grep -c '"id"' || echo "0")
            if [ "$vuln_count" -gt 0 ]; then
                add_finding "HIGH" "DEP003" "Known vulnerabilities in Python dependencies" \
                    "pip-audit found ${vuln_count} known vulnerability/vulnerabilities" \
                    "$TARGET_DIR" \
                    "Run 'pip-audit' and update affected packages"
            fi
        fi
        found_audit=true
    fi

    # Node.js: npm audit
    while IFS= read -r pkgjson; do
        [ -z "$pkgjson" ] && continue
        local pkg_dir
        pkg_dir=$(dirname "$pkgjson")
        if [ -f "${pkg_dir}/package-lock.json" ] && command -v npm &>/dev/null; then
            local audit_output
            audit_output=$(cd "$pkg_dir" && npm audit --json 2>/dev/null || true)
            if [ -n "$audit_output" ]; then
                local vuln_total
                vuln_total=$(echo "$audit_output" | grep -oE '"total":\s*[0-9]+' | head -1 | grep -oE '[0-9]+' || echo "0")
                if [ "$vuln_total" -gt 0 ]; then
                    add_finding "HIGH" "DEP003" "Known vulnerabilities in Node.js dependencies" \
                        "npm audit found ${vuln_total} vulnerability/vulnerabilities" \
                        "$pkg_dir" \
                        "Run 'npm audit fix' to resolve known vulnerabilities"
                fi
            fi
            found_audit=true
        fi
    done < <(find "$TARGET_DIR" -name "package.json" -maxdepth 3 \
        -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null || true)

    if [ "$found_audit" = false ]; then
        add_finding "INFO" "DEP003" "No dependency audit tool available" \
            "Consider installing pip-audit (Python) or using npm audit (Node.js)" \
            "$TARGET_DIR" \
            "Install a vulnerability scanner for your package ecosystem"
    fi
}

# ============================================================
# CHECK 5: Docker image sources
# ============================================================
check_docker_images() {
    while IFS= read -r dockerfile; do
        [ -z "$dockerfile" ] && continue
        while IFS= read -r match; do
            [ -z "$match" ] && continue
            local line_num image_name
            line_num=$(echo "$match" | cut -d: -f1)
            image_name=$(echo "$match" | sed -E 's/^[0-9]+:\s*FROM\s+//i' | awk '{print $1}')

            # Check for :latest tag or no tag
            if echo "$image_name" | grep -qE ':latest$' || ! echo "$image_name" | grep -qE ':'; then
                add_finding "MEDIUM" "DEP004" "Docker image without pinned version" \
                    "Image '${image_name}' uses :latest or no version tag" \
                    "${dockerfile}:${line_num}" \
                    "Pin Docker image to a specific version tag or SHA256 digest"
            fi

            # Check for unofficial/unknown base images
            if ! echo "$image_name" | grep -qE '^(docker\.io/|ghcr\.io/|gcr\.io/|quay\.io/|mcr\.microsoft\.com/|public\.ecr\.aws/|registry\.|localhost)' && \
               echo "$image_name" | grep -qE '/.*/' ; then
                add_finding "LOW" "DEP005" "Docker image from potentially untrusted registry" \
                    "Image '${image_name}' may not be from an official registry" \
                    "${dockerfile}:${line_num}" \
                    "Verify the image source and consider using official/verified images"
            fi
        done < <(grep -niE '^\s*FROM\s+' "$dockerfile" 2>/dev/null || true)
    done < <(find "$TARGET_DIR" \( -name "Dockerfile" -o -name "Dockerfile.*" -o -name "*.dockerfile" \) \
        -not -path "*/.git/*" 2>/dev/null || true)

    # Check docker-compose for image sources
    while IFS= read -r composefile; do
        [ -z "$composefile" ] && continue
        while IFS= read -r match; do
            [ -z "$match" ] && continue
            local line_num image_name
            line_num=$(echo "$match" | cut -d: -f1)
            image_name=$(echo "$match" | sed -E 's/^[0-9]+:\s*image:\s*//i' | tr -d '"'"'"' ' | tr -d "'")
            [ -z "$image_name" ] && continue
            if echo "$image_name" | grep -qE ':latest$' || ! echo "$image_name" | grep -qE ':'; then
                add_finding "MEDIUM" "DEP004" "Docker Compose image without pinned version" \
                    "Image '${image_name}' uses :latest or no version tag" \
                    "${composefile}:${line_num}" \
                    "Pin image to a specific version tag"
            fi
        done < <(grep -niE '^\s*image:\s*' "$composefile" 2>/dev/null || true)
    done < <(find "$TARGET_DIR" \( -name "docker-compose*.yml" -o -name "docker-compose*.yaml" -o -name "compose*.yml" -o -name "compose*.yaml" \) \
        -not -path "*/.git/*" 2>/dev/null || true)
}

# ============================================================
# Main
# ============================================================
emit_header "dependencies" "$TARGET_DIR"

check_python_deps
check_node_deps
check_go_deps
check_vulnerability_audit
check_docker_images

emit_footer "dependencies"
