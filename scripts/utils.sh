#!/usr/bin/env bash
# ClawSafe - Shared Utilities for Check Scripts
# Sourced by all check_*.sh scripts

# Append a JSON finding to stdout
# Usage: add_finding SEVERITY CHECK_ID TITLE DETAIL LOCATION SUGGESTION
add_finding() {
    local severity="$1"
    local check_id="$2"
    local title="$3"
    local detail="$4"
    local location="$5"
    local suggestion="$6"

    # Escape for JSON
    detail=$(printf '%s' "$detail" | sed 's/\\/\\\\/g; s/"/\\"/g; s/\t/\\t/g' | tr '\n' ' ')
    location=$(printf '%s' "$location" | sed 's/\\/\\\\/g; s/"/\\"/g')
    suggestion=$(printf '%s' "$suggestion" | sed 's/\\/\\\\/g; s/"/\\"/g')
    title=$(printf '%s' "$title" | sed 's/\\/\\\\/g; s/"/\\"/g')

    echo "{\"severity\":\"${severity}\",\"check_id\":\"${check_id}\",\"title\":\"${title}\",\"detail\":\"${detail}\",\"location\":\"${location}\",\"suggestion\":\"${suggestion}\"}"
}

# Emit a header JSON line for a check category
emit_header() {
    local category="$1"
    local target="$2"
    echo "### ClawSafe ${category} Check ###"
    echo "{\"check_category\":\"${category}\",\"target\":\"${target}\",\"timestamp\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"os\":\"$(uname -s)\",\"user\":\"$(whoami 2>/dev/null || echo unknown)\",\"hostname\":\"$(hostname 2>/dev/null || echo unknown)\"}"
}

# Emit a footer JSON line
emit_footer() {
    local category="$1"
    echo "{\"check_category\":\"${category}\",\"status\":\"complete\"}"
}
