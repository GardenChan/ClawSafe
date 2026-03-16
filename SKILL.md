---
name: clawsafe
description: "This skill should be used when users want to perform a security self-check on their AI Agent runtime environment, especially OpenClaw Gateway deployments. It audits OpenClaw configuration (gateway binding, DM/group policies, sandbox mode, tool permissions, skill secrets, webhook tokens, plugin security), detects hardcoded secrets, sensitive file exposure, network port risks, dependency vulnerabilities, and log data leaks. Trigger keywords: security check, security scan, self-check, safety audit, vulnerability scan, openclaw audit, gateway security, 安全检测, 安全自检, 安全扫描."
---

# ClawSafe — AI Agent Security Self-Check

## Overview

ClawSafe is a security self-check skill purpose-built for AI Agent runtime environments, with first-class support for **OpenClaw Gateway** deployments. It runs a suite of cross-platform shell scripts to identify security misconfigurations and risks, then synthesizes findings into a severity-graded report.

**Key design principles:**
- **Read-only detection** — no files are modified during scanning
- **Cross-platform** — all scripts support Linux, macOS, and container environments
- **Zero path assumptions** — OpenClaw paths are dynamically discovered, never hardcoded
- **Sensitive data redaction** — secrets found are masked in output (first 4 characters only)
- **Not a replacement for professional security audit** — always include this disclaimer

## OpenClaw Path Discovery

**CRITICAL: ClawSafe never assumes any hardcoded path for OpenClaw.**

OpenClaw installations vary widely — users can customize paths via environment variables, run multiple instances, use service accounts, or deploy in containers. The `check_openclaw.sh` script uses a multi-strategy discovery engine:

### Discovery Strategies (in priority order)

1. **Explicit argument** — if the user passes a path, use it directly
2. **`openclaw` CLI** — query the running gateway for its actual config (most reliable)
3. **Environment variables** — check `OPENCLAW_CONFIG_PATH`, `OPENCLAW_STATE_DIR`, `OPENCLAW_HOME`
4. **Running process inspection** — read `/proc/<pid>/environ` or process command line
5. **Filesystem search** — search under `$HOME` with limited depth (last resort)

### Key OpenClaw Environment Variables

| Variable | Purpose | Default |
|----------|---------|---------|
| `OPENCLAW_HOME` | Overrides all internal path resolution (replaces `$HOME`) | System `$HOME` |
| `OPENCLAW_STATE_DIR` | Overrides state directory path | `$OPENCLAW_HOME/.openclaw` |
| `OPENCLAW_CONFIG_PATH` | Overrides config file path | `$OPENCLAW_STATE_DIR/openclaw.json` |

The discovery result (method used, paths found) is always emitted as finding `OC000` so the user can verify what was actually checked.

## Workflow

### Step 1: Detect Environment

Run the OpenClaw discovery engine. The script will:
1. Try to find the `openclaw` CLI binary (PATH, npx, running processes)
2. Query the CLI for live configuration if available
3. Fall back through environment variables and process inspection
4. Report exactly what was discovered and how

If OpenClaw is detected, automatically include the OpenClaw configuration audit. If not detected, skip OpenClaw checks and inform the user with guidance on how to make it discoverable (e.g., setting `OPENCLAW_STATE_DIR`).

**Never assume paths like `~/.openclaw` — always use the discovery engine.**

### Step 2: Determine Scan Scope

Identify the target directory for general checks (default: current project root). The OpenClaw audit uses discovered paths.

Available scan scopes:
- **Full scan** — all modules including OpenClaw audit (recommended)
- **OpenClaw only** — just the OpenClaw configuration audit
- **General only** — environment, files, network, dependencies (skip OpenClaw)
- **Single module** — run one specific check script

### Step 3: Run Detection Scripts

Execute the detection scripts from `scripts/` relative to this skill's base directory.

**Full scan entry point:**

```bash
bash "${SKILL_DIR}/scripts/run_all.sh" "<target_directory>"
```

**Individual modules:**

| Script | Category | Key Checks |
|--------|----------|------------|
| `scripts/check_openclaw.sh` | **OpenClaw Config** | Auto-discovery, gateway binding, DM/group policies, sandbox mode, tool permissions, skill secrets, webhooks, cron, logging, mDNS, multi-agent isolation, session security, SSRF, plugin hooks |
| `scripts/check_env.sh` | Environment Config | API key hardcoding, .env git tracking, file permissions, default values |
| `scripts/check_files.sh` | File System | Sensitive file access, system dir write perms, log leaks, temp file residue, key files in project |
| `scripts/check_network.sh` | Network Exposure | Port binding, HTTPS config, CORS policy, public IP |
| `scripts/check_deps.sh` | Dependencies | Version pinning, lock files, CVE audit, Docker image sources |

The OpenClaw audit auto-discovers paths. You can optionally pass an explicit state directory:

```bash
# Auto-discover (recommended)
bash "${SKILL_DIR}/scripts/check_openclaw.sh"

# Explicit override (if auto-discovery fails or for custom setups)
bash "${SKILL_DIR}/scripts/check_openclaw.sh" "/custom/path/to/openclaw/state"

# Via environment variable
OPENCLAW_STATE_DIR="/custom/path" bash "${SKILL_DIR}/scripts/check_openclaw.sh"
```

Each script outputs **JSON lines** — one JSON object per finding, plus header/footer lines.

### Step 4: Parse Results

Parse the JSON lines output. Each finding has the structure:

```json
{
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "check_id": "OC001",
  "title": "Short description",
  "detail": "Detailed explanation with masked sensitive data",
  "location": "file/path:line_number",
  "suggestion": "Remediation advice"
}
```

Check ID prefixes indicate category:
- `OC*` — OpenClaw configuration (includes `OC000` discovery report)
- `ENV*` — Environment configuration
- `FS*` — File system
- `NET*` — Network exposure
- `DEP*` — Dependencies

### Step 5: Generate Report

Synthesize all findings into a structured report. Refer to `references/checklist.md` for the full checklist and `assets/report_template.md` for the format.

**Report generation rules:**

1. **Discovery context** — always report which discovery method was used (`OC000`) and what paths were actually inspected
2. **Severity counts** — aggregate by level (CRITICAL / HIGH / MEDIUM / LOW / INFO)
3. **Grouping** — organize by category. Put **OpenClaw Config** findings first if present.
4. **Redaction** — never include raw secret values; use masked form only
5. **Remediation** — include the `suggestion` field for every finding, with OpenClaw-specific config snippets where applicable
6. **OpenClaw context** — when reporting OpenClaw findings, reference the relevant OpenClaw documentation section
7. **Disclaimer** — always end with: "⚠️ This report is for reference only and cannot replace a professional security audit"
8. **Scope note** — clearly state what was and was NOT checked, including which paths were inspected
9. **Built-in command reminder** — mention `openclaw security audit` for complementary checking

### Step 6: Present Results

Present the report to the user. Offer to:
- Re-run specific check modules for deeper investigation
- Explain any finding in detail with OpenClaw documentation context
- Help implement remediation (provide exact config JSON5 snippets)
- Compare current config against OpenClaw security best practices
- Run `openclaw doctor --fix` for auto-fixable config issues
- Re-run with explicit paths if discovery didn't find the expected installation

## OpenClaw Security Best Practices Reference

When generating remediation advice for OpenClaw findings, use these recommended configurations as baseline:

**Minimal secure Gateway config:**
```json5
{
  agents: {
    defaults: {
      sandbox: { mode: "non-main", backend: "docker", scope: "agent" },
    },
  },
  tools: {
    deny: ["gateway", "cron", "sessions_spawn"],
    elevated: { enabled: false },
  },
  gateway: {
    bind: "loopback",
    auth: { token: "${GATEWAY_TOKEN}" },
  },
  channels: {
    whatsapp: { dmPolicy: "pairing" },
  },
  logging: { redactSensitive: true },
  discovery: {
    mdns: { mode: "minimal" },
  },
}
```

**Key principles from OpenClaw security model:**
- OpenClaw follows a **personal assistant security model** — one trusted operator per Gateway instance
- State directory should be `700`, config files and credentials `600`
- Use `SecretRef` objects for API keys, never inline strings
- The `sessionKey` is a routing selector, NOT an authentication token
- For multi-user scenarios, set `session.dmScope: "per-channel-peer"` for context isolation
- Third-party skills should be treated as untrusted code — review before use
- Use the `pairing` DM policy (default) rather than `open`
- Deny control-plane tools (`gateway`, `cron`, `sessions_spawn`) unless explicitly needed
- Use `OPENCLAW_STATE_DIR` or `OPENCLAW_CONFIG_PATH` for custom installations

## Important Notes

- **Self-check trustworthiness**: Since the Agent runs these checks on its own environment, results could theoretically be tampered with if the environment is compromised. Recommend users verify critical findings independently.
- **Permission requirements**: Some checks (network ports, system file access) may require elevated privileges. Report which checks were skipped due to insufficient permissions.
- **Performance**: Log file scanning is limited to the last 1000 lines per file. Temp file scanning covers files modified within the last 24 hours.
- **Path portability**: The OpenClaw audit auto-discovers paths using CLI, env vars, and process inspection. It never assumes `~/.openclaw` or any other fixed path. If discovery fails, it clearly reports what was tried and how to help it find the installation.
- **Complementary tools**: Recommend users also run `openclaw security audit` and `openclaw doctor` for OpenClaw's built-in validation.
