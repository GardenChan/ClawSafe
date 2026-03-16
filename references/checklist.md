# ClawSafe Detection Checklist

Complete list of all security checks performed by ClawSafe, organized by category.

---

## 0. OpenClaw Configuration Audit

> These checks are **specific to OpenClaw Gateway deployments**. The script **auto-discovers** the OpenClaw installation using multiple strategies (CLI, environment variables, process inspection, filesystem search). **No paths are hardcoded.**

### Path Discovery

| Priority | Strategy | Description |
|----------|----------|-------------|
| 1 | Explicit argument | User passes path directly to the script |
| 2 | `openclaw` CLI | Query the running gateway for its live config |
| 3 | `OPENCLAW_CONFIG_PATH` env | Direct path to config file |
| 4 | `OPENCLAW_STATE_DIR` env | Direct path to state directory |
| 5 | `OPENCLAW_HOME` env | Overrides `$HOME` for all path resolution |
| 6 | Process inspection | Read env/cwd from running `openclaw` process |
| 7 | Filesystem search | Search under `$HOME` with depth limit (last resort) |

### Check Items

| ID | Check | Severity | Script |
|----|-------|----------|--------|
| OC000 | Discovery report (what was found, which method used) | INFO | check_openclaw.sh |
| OC001 | State dir / config / auth / credential file permissions | HIGH | check_openclaw.sh |
| OC002 | Gateway bound to non-loopback / missing auth / weak token | CRITICAL/HIGH/MEDIUM | check_openclaw.sh |
| OC003 | DM/Group policy too open / wildcard allowFrom | HIGH/MEDIUM | check_openclaw.sh |
| OC004 | Sandbox mode disabled or misconfigured / policy drift | HIGH/MEDIUM/LOW | check_openclaw.sh |
| OC005 | Elevated tools enabled / no tool deny list | HIGH/MEDIUM | check_openclaw.sh |
| OC006 | Skill API key hardcoded / third-party skill risk | HIGH/INFO | check_openclaw.sh |
| OC007 | Webhook hooks without token / unsafe content | CRITICAL/HIGH | check_openclaw.sh |
| OC008 | Cron tool accessible to agents | MEDIUM | check_openclaw.sh |
| OC009 | Sensitive log redaction disabled | HIGH/LOW | check_openclaw.sh |
| OC010 | mDNS broadcasting internal info | MEDIUM | check_openclaw.sh |
| OC011 | Multi-agent isolation issues (shared agentDir/workspace) | CRITICAL/MEDIUM | check_openclaw.sh |
| OC012 | Session storage directory / file permissions | HIGH/MEDIUM | check_openclaw.sh |
| OC013 | Browser SSRF private network access allowed | MEDIUM | check_openclaw.sh |
| OC014 | Plugin prompt injection / no plugin allowlist | HIGH/MEDIUM | check_openclaw.sh |
| OC015 | .env files within OpenClaw state directory permissions | HIGH | check_openclaw.sh |

### OC000 — Discovery Report

**What it does:** Reports which discovery method was used, what paths were found (state directory, config file, CLI binary), and whether the installation was detected at all.

**Why it matters:** Without this transparency, users cannot verify that the correct OpenClaw installation was audited. This is especially important in multi-instance, containerized, or service-account deployments where the installation may not be in the default location.

**If discovery fails:** The finding will list all strategies attempted and suggest setting `OPENCLAW_STATE_DIR` or `OPENCLAW_CONFIG_PATH` environment variables, or ensuring `openclaw` is in `PATH`.

### OC001 — State Directory & File Permissions

**What it checks:**
- OpenClaw state directory should be `700` (owner-only access)
- Config file should not be world-readable
- `auth-profiles.json` files (dynamically discovered) should not be world-readable
- `creds.json` credential files (dynamically discovered) should not be world-readable

**Why it matters:** The state directory contains credentials, session histories (which may include sensitive conversations), auth profiles with API keys, and the full gateway configuration. Loose permissions expose all of this to other users on the system.

**Note:** Paths are discovered dynamically — the script searches for `auth-profiles.json` and `creds.json` within the discovered state directory rather than assuming any specific subdirectory structure.

### OC002 — Gateway Network Binding

**What it checks:**
- Whether `gateway.bind` is set to `lan`, `tailnet`, or `0.0.0.0` (non-loopback)
- If binding is non-loopback, whether `gateway.auth` (token/password) is configured
- Whether auth tokens are too short (< 8 characters)

**Severity:** CRITICAL if exposed without auth, HIGH if exposed to LAN or weak token, MEDIUM for tailnet.

**Context:** The OpenClaw Control UI provides full gateway management including chat, configuration, and session access. Without authentication, anyone on the network can control the agent.

### OC003 — DM and Group Access Policies

**What it checks:**
- `dmPolicy: "open"` — allows anyone to DM the bot
- `allowFrom: ["*"]` — wildcard sender whitelist
- `groupPolicy: "open"` — any group member can trigger bot
- `requireMention: false` — bot responds to all group messages without @mention

**Context:** OpenClaw's default `dmPolicy` is `"pairing"` (unknown senders need a one-time pairing code). Changing to `"open"` removes this protection entirely. The `requireMention` guard prevents accidental triggers in noisy group chats.

### OC004 — Sandbox Configuration

**What it checks:**
- `sandbox.mode: "off"` — agent has full host access
- No sandbox configuration at all
- `workspaceAccess: "rw"` in sandbox (agent can modify workspace files)
- Docker sandbox `network` set to "host" or "bridge" (not isolated)
- **Policy drift:** Docker backend configured but sandbox mode set to off

**Context:** OpenClaw supports Docker-based sandboxing that isolates agent tool execution. Without sandboxing, an agent (or a prompt injection attack) can execute arbitrary commands on the host, read/write any file, and access the network.

### OC005 — Tool Permissions

**What it checks:**
- `tools.elevated.enabled: true` — grants host exec with elevated privileges
- `tools.profile: "full"` — all tools available
- No `tools.deny` list configured

**Recommended deny list:** `["gateway", "cron", "sessions_spawn"]` per OpenClaw security documentation. These are control-plane tools that allow modifying gateway configuration, creating scheduled tasks, and spawning new sessions.

### OC006 — Skill Security

**What it checks:**
- Inline `apiKey` strings in `skills.entries.*` (should use `SecretRef` instead)
- Third-party skills within the discovered state directory (dynamically found)
- Whether `skills.allowBundled` is configured to limit loaded skills

**Context:** OpenClaw docs state: "treat third-party skills as untrusted code." Skill `env` and `apiKey` injection goes to the host process (not sandbox), so leaked keys bypass isolation.

### OC007 — Webhook/Hooks Security

**What it checks:**
- Hooks enabled without a shared `token` secret
- `allowUnsafeExternalContent: true` flag

**Context:** Without a shared secret, anyone who discovers the webhook endpoint can trigger agent actions. The unsafe content flag disables payload sanitization.

### OC008 — Cron Job Security

**What it checks:** Whether the `cron` tool is in the deny list when cron is enabled.

**Context:** If cron is enabled and the cron tool is not denied, agents can create their own scheduled tasks, potentially leading to persistent unauthorized actions.

### OC009 — Logging Redaction

**What it checks:**
- `logging.redactSensitive: false` (explicitly disabled)
- No explicit `redactSensitive: true` setting

**Context:** Without redaction, API keys, tokens, and other secrets may leak into log files.

### OC010 — mDNS/Bonjour Exposure

**What it checks:** `discovery.mdns.mode: "full"` broadcasts `cliPath`, `sshPort`, and other internal information to the local network.

**Recommended:** Set to `"minimal"` or `"off"`, or set `OPENCLAW_DISABLE_BONJOUR=1`.

### OC011 — Multi-Agent Isolation

**What it checks:**
- Multiple agents sharing the same `agentDir` (causes auth/session conflicts)
- Multiple agents without explicit workspace paths (may share default workspace)

**Context:** OpenClaw docs state: "Never reuse `agentDir` across agents — this causes authentication and session conflicts." Each agent should have unique `agentDir` and `workspace`.

### OC012 — Session Storage Permissions

**What it checks:**
- Session directories (dynamically discovered via `find`) have proper permissions
- Individual session JSONL files are not world-readable

**Why it matters:** Session files contain full conversation histories in JSONL format, which may include sensitive information shared by users.

### OC013 — Browser SSRF Policy

**What it checks:** `browser.ssrfPolicy.dangerouslyAllowPrivateNetwork: true`.

**Context:** When true, the agent's browser tool can access internal services (e.g., metadata endpoints, internal APIs). Default is true (trusted operator model), but should be false in shared environments.

### OC014 — Plugin Security

**What it checks:**
- `plugins.entries.*.hooks.allowPromptInjection: true` — plugin can modify system prompt
- Plugins/extensions installed (dynamically discovered) without an allowlist configured

**Context:** This flag allows a plugin to modify the agent's system prompt, fundamentally altering its behavior. Only trusted, audited plugins should have this permission.

### OC015 — OpenClaw .env File Permissions

**What it checks:** `.env` and `.env.*` files within the OpenClaw state directory have proper permissions (not world-readable).

**Why it matters:** OpenClaw loads `.env` files from its state directory as a global fallback for environment variables. These files often contain API keys and other secrets.

---

## 1. Environment Configuration Security

| ID | Check | Severity | Script |
|----|-------|----------|--------|
| ENV001 | API Key / Secret hardcoded in config files | HIGH | check_env.sh |
| ENV002 | .env file tracked by git | CRITICAL | check_env.sh |
| ENV003 | .env not listed in .gitignore | MEDIUM/LOW | check_env.sh |
| ENV004 | Config file permissions too open (world-readable/writable) | MEDIUM/HIGH | check_env.sh |
| ENV005 | Default/placeholder values remain in config | MEDIUM | check_env.sh |

### ENV001 — Hardcoded Secrets

**What it checks:** Scans configuration and source files for patterns matching common API keys, tokens, passwords, and secrets. Covers:
- Generic `api_key`, `secret_key`, `password`, `token` patterns
- Provider-specific: `OPENAI_API_KEY` (sk-...), `ANTHROPIC_API_KEY` (sk-ant-...), `AWS_SECRET_ACCESS_KEY`

**File types scanned:** yaml, yml, json, toml, ini, cfg, conf, py, js, ts

**Exclusions:** node_modules, .git, venv, __pycache__, .venv, env

### ENV002 — .env Git Tracking

**What it checks:** Verifies that `.env` and `.env.*` files (excluding `.env.example`, `.env.template`, `.env.sample`) are not tracked by git.

### ENV003 — .gitignore Coverage

**What it checks:** Confirms that `.gitignore` includes `.env` exclusion patterns.

### ENV004 — File Permissions

**What it checks:** Inspects UNIX permissions on files with sensitive extensions (.pem, .key, .p12, .pfx, etc.) and names containing "secret", "credential", "password", "token". Flags world-readable (o+r) and world-writable (o+w).

**Cross-platform:** Uses `stat -f` on macOS, `stat -c` on Linux.

### ENV005 — Default Values

**What it checks:** Searches config files for common placeholder strings: `changeme`, `REPLACE_ME`, `your_api_key`, `placeholder`, `admin:admin`, `root:root`, `TODO: replace`, etc.

---

## 2. File System Security

| ID | Check | Severity | Script |
|----|-------|----------|--------|
| FS001 | Agent can read sensitive system files | CRITICAL/HIGH/MEDIUM | check_files.sh |
| FS002 | Agent has write access to system directories | CRITICAL/HIGH/LOW | check_files.sh |
| FS003 | Log files contain sensitive data patterns | HIGH | check_files.sh |
| FS004 | Temp files with sensitive data residue | MEDIUM | check_files.sh |
| FS005 | Private key/certificate files in project | HIGH | check_files.sh |

### FS001 — Sensitive File Access

**Files checked:**
- System: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`
- SSH: `~/.ssh/id_rsa`, `~/.ssh/id_ed25519`, `~/.ssh/config`
- Cloud: `~/.aws/credentials`, `~/.kube/config`, `~/.gcloud/credentials.db`, `~/.azure/accessTokens.json`
- Package managers: `~/.npmrc`, `~/.pypirc`, `~/.netrc`
- History: `~/.bash_history`, `~/.zsh_history`
- Docker: `~/.docker/config.json`
- GPG: `~/.gnupg/secring.gpg`

### FS002 — System Write Access

**Directories checked:** `/etc`, `/usr/bin`, `/usr/local/bin`, `/var/log`, `/tmp`, `/var/tmp`

CRITICAL for system dirs (`/etc`, `/usr/bin`), LOW for expected-writable dirs (`/tmp`).

### FS003 — Log Sensitive Data

**Patterns scanned:** password, api_key, secret, token, Authorization Bearer, X-API-Key, sk- prefixed keys.

Limited to last 1000 lines per log file for performance.

### FS004 — Temp File Residue

**Scope:** Files in `/tmp`, `/var/tmp`, `$TMPDIR` owned by current user, modified within last 24 hours, checking first 4KB for sensitive patterns.

### FS005 — Sensitive Files in Project

**Extensions flagged:** .pem, .key, .p12, .pfx, .jks, .keystore

---

## 3. Network Exposure

| ID | Check | Severity | Script |
|----|-------|----------|--------|
| NET001 | Service ports bound to 0.0.0.0 | MEDIUM | check_network.sh |
| NET002 | Non-HTTPS URLs / SSL disabled | MEDIUM/HIGH | check_network.sh |
| NET003 | CORS allows all origins (*) | HIGH | check_network.sh |
| NET005 | Public IP address hardcoded in config | MEDIUM | check_network.sh |

### NET001 — Port Binding

**How it checks:**
- macOS: `lsof -iTCP -sTCP:LISTEN`
- Linux: `ss -tlnp` or `netstat -tlnp`

Flags any service listening on `0.0.0.0` or `*` (all interfaces).

### NET002 — HTTPS / SSL

**Two sub-checks:**
1. Non-localhost `http://` URLs in config files
2. Explicit `ssl=false`, `tls=off`, `verify_ssl=false` patterns

**Exclusions:** localhost, 127.0.0.1, example.com, template variables ($, {, <), JSON $schema refs.

### NET003 — CORS

**Patterns:** `allow_origins=*`, `Access-Control-Allow-Origin: *`, `cors.*origin.*\*`

### NET005 — Public IP

Detects IP addresses in config files that are NOT private (10.x, 172.16-31.x, 192.168.x), loopback (127.x), or link-local (169.254.x).

---

## 4. Dependency Security

| ID | Check | Severity | Script |
|----|-------|----------|--------|
| DEP001 | Unpinned dependency versions | MEDIUM | check_deps.sh |
| DEP002 | Missing lock file | MEDIUM | check_deps.sh |
| DEP003 | Known CVE vulnerabilities | HIGH | check_deps.sh |
| DEP004 | Docker image without pinned version | MEDIUM | check_deps.sh |
| DEP005 | Docker image from untrusted registry | LOW | check_deps.sh |

### DEP001 — Version Pinning

**Python:** Checks `requirements*.txt` for packages without `==`, `>=`, `<=`, `~=` specifiers.

### DEP002 — Lock Files

**Checked for:**
- Python: `poetry.lock`, `Pipfile.lock`, `pdm.lock`, `uv.lock`
- Node.js: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
- Go: `go.sum`

### DEP003 — CVE Audit

Runs available audit tools:
- Python: `pip-audit` (if installed)
- Node.js: `npm audit` (if package-lock.json present)

Reports finding count if vulnerabilities detected.

### DEP004/DEP005 — Docker Images

Checks `Dockerfile` and `docker-compose*.yml` for:
- `:latest` tag or missing version tag
- Images from potentially untrusted registries (not docker.io, ghcr.io, gcr.io, quay.io, etc.)
