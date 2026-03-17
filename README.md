# 🛡️ ClawSafe

**Security self-check tool for AI Agent runtime environments, purpose-built for [OpenClaw Gateway](https://docs.openclaw.ai).**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[📖 中文文档](README.zh-CN.md)

ClawSafe is an OpenClaw Skill that runs a suite of cross-platform shell scripts to audit your AI Agent's runtime environment, identify security misconfigurations, and generate a severity-graded report.

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🔍 35 security checks
  🐾 16 OpenClaw-specific checks
  🖥️  Linux / macOS / containers
  🔒 Read-only — no files modified
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## ✨ Features

- **Zero path assumptions** — OpenClaw installation paths are dynamically discovered via a multi-strategy engine (CLI / env vars / process inspection / filesystem search), never hardcoded
- **35 security checks** — covering OpenClaw config, environment variables, file system, network exposure, and dependency security
- **Read-only safe** — all scripts only read information; no files or configurations are ever modified
- **Sensitive data redaction** — discovered secrets/tokens are masked (first 4 characters only)
- **JSON Lines output** — structured output for easy integration and automation
- **Cross-platform** — supports Linux, macOS, and container environments

## 📦 Installation

### Option 1: Global install (recommended, shared across all Agents)

```bash
git clone https://github.com/GardenChan/ClawSafe.git ~/.openclaw/skills/clawsafe
```

> If your OpenClaw state directory is not in the default location:
> ```bash
> git clone https://github.com/GardenChan/ClawSafe.git "$OPENCLAW_STATE_DIR/skills/clawsafe"
> ```

### Option 2: Workspace install (current project only, highest priority)

```bash
cd /your/project/workspace
mkdir -p skills
git clone https://github.com/GardenChan/ClawSafe.git skills/clawsafe
```

### Option 3: Custom directory

Clone to any location, then configure in `openclaw.json`:

```bash
git clone https://github.com/GardenChan/ClawSafe.git /path/to/my-skills/clawsafe
```

```json5
{
  skills: {
    load: {
      extraDirs: ["/path/to/my-skills"]
    }
  }
}
```

OpenClaw will automatically detect and load the Skill after installation — no restart required.

## ⚡ Quick Start

Copy the following message and send it to your OpenClaw Agent — that's it:

```
Help me run a security self-check on the current environment using the ClawSafe skill.
Check OpenClaw configuration, environment variables, file permissions, network exposure,
and dependency security. Generate a full report with severity ratings and remediation suggestions.
```

## 🚀 Usage

### Via OpenClaw Agent conversation

Once installed, simply tell your Agent:

> "run a security scan"
>
> "check OpenClaw security config"
>
> "perform a security self-check"

The Agent will automatically invoke ClawSafe and generate a report.

### Run scripts directly

You can also run ClawSafe independently of OpenClaw:

```bash
# Full scan (current directory)
bash scripts/run_all.sh

# Full scan (specify target directory)
bash scripts/run_all.sh /path/to/project

# OpenClaw config audit only (auto-discover paths)
bash scripts/check_openclaw.sh

# Specify OpenClaw state directory explicitly
bash scripts/check_openclaw.sh /custom/openclaw/state

# Via environment variable
OPENCLAW_STATE_DIR="/custom/path" bash scripts/check_openclaw.sh

# Run individual modules
bash scripts/check_env.sh /path/to/project
bash scripts/check_files.sh /path/to/project
bash scripts/check_network.sh /path/to/project
bash scripts/check_deps.sh /path/to/project
```

## 🔍 Check Overview

### 🐾 OpenClaw Configuration Audit (16 checks)

| ID | Check | Severity |
|----|-------|----------|
| OC000 | Discovery report (strategy used, paths found) | INFO |
| OC001 | State dir / config / auth / credential file permissions | HIGH |
| OC002 | Gateway bound to non-loopback / missing auth / weak token | CRITICAL ~ MEDIUM |
| OC003 | DM/Group policy too open / wildcard allowFrom | HIGH ~ MEDIUM |
| OC004 | Sandbox mode disabled or misconfigured / policy drift | HIGH ~ LOW |
| OC005 | Elevated tools enabled / no tool deny list | HIGH ~ MEDIUM |
| OC006 | Skill API key hardcoded / third-party skill risk | HIGH ~ INFO |
| OC007 | Webhook without token / unsafe content allowed | CRITICAL ~ HIGH |
| OC008 | Cron tool accessible to agents | MEDIUM |
| OC009 | Sensitive log redaction disabled | HIGH ~ LOW |
| OC010 | mDNS broadcasting internal info | MEDIUM |
| OC011 | Multi-agent isolation issues (shared agentDir/workspace) | CRITICAL ~ MEDIUM |
| OC012 | Session storage directory / file permissions | HIGH ~ MEDIUM |
| OC013 | Browser SSRF private network access allowed | MEDIUM |
| OC014 | Plugin prompt injection / no plugin allowlist | HIGH ~ MEDIUM |
| OC015 | OpenClaw .env file permissions | HIGH |

### 🔒 Environment Config (ENV)

Hardcoded API keys, `.env` tracked by Git, improper file permissions, default values in use, etc.

### 📁 File System (FS)

Sensitive file exposure, system directory write permissions, log data leaks, temp file residue, key files in project, etc.

### 🌐 Network Exposure (NET)

Port binding, HTTPS configuration, CORS policies, public IP exposure, etc.

### 📦 Dependency Security (DEP)

Unpinned versions, missing lock files, CVE vulnerability audit, Docker image sources, etc.

> 📋 Full checklist with detailed explanations: [`references/checklist.md`](references/checklist.md)

## 🧭 OpenClaw Path Discovery

ClawSafe **never assumes any fixed path**. `check_openclaw.sh` dynamically discovers paths via a multi-strategy engine:

| Priority | Strategy | Description |
|----------|----------|-------------|
| 1 | Explicit argument | User passes path directly |
| 2 | `openclaw` CLI | Query running Gateway for live config (most reliable) |
| 3 | `OPENCLAW_CONFIG_PATH` env | Direct path to config file |
| 4 | `OPENCLAW_STATE_DIR` env | Direct path to state directory |
| 5 | `OPENCLAW_HOME` env | Overrides `$HOME` for path resolution |
| 6 | Process inspection | Read env/cmdline from running `openclaw` process |
| 7 | Filesystem search | Search under `$HOME` with depth limit (last resort) |

Discovery results are always emitted as finding `OC000` so users can verify what was actually inspected.

## 📊 Output Format

Each check emits one JSON Line:

```json
{
  "severity": "HIGH",
  "check_id": "OC002",
  "title": "Gateway bound to LAN without authentication",
  "detail": "gateway.bind is set to 'lan' but no auth token is configured",
  "location": "openclaw.json:gateway.bind",
  "suggestion": "Set gateway.auth.token or change bind to 'loopback'"
}
```

Report template: [`assets/report_template.md`](assets/report_template.md)

## 📂 Project Structure

```
ClawSafe/
├── SKILL.md                    # OpenClaw Skill definition (entry point)
├── README.md                   # This file (English)
├── README.zh-CN.md             # Chinese documentation
├── LICENSE                     # MIT License
├── scripts/
│   ├── run_all.sh              # Full scan entry point
│   ├── check_openclaw.sh       # OpenClaw config audit (with discovery engine)
│   ├── check_env.sh            # Environment variable checks
│   ├── check_files.sh          # File system checks
│   ├── check_network.sh        # Network exposure checks
│   ├── check_deps.sh           # Dependency security checks
│   └── utils.sh                # Shared utility functions
├── assets/
│   └── report_template.md      # Report template
└── references/
    └── checklist.md            # Full checklist with detailed explanations
```

## 🤝 Complementary Tools

ClawSafe is a supplementary tool. We recommend also using OpenClaw's built-in commands:

```bash
# OpenClaw built-in security audit
openclaw security audit

# Auto-fix common configuration issues
openclaw doctor --fix
```

## ⚠️ Disclaimer

ClawSafe is an auxiliary security self-check tool and **cannot replace a professional security audit**. Checks are executed by the Agent within its own environment — if the environment is already compromised, results may not be trustworthy. We recommend independently verifying critical findings.

## 📄 License

[MIT](LICENSE) © garden
