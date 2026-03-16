# ClawSafe Security Self-Check Report

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  ClawSafe Security Self-Check Report
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

**Scan Time:** {{timestamp}}
**Target Directory:** {{target_directory}}
**OpenClaw Detected:** {{openclaw_detected ? "✅ Yes" : "❌ No"}}
**Discovery Method:** {{discovery_method}} {{#if openclaw_state_dir}}| State Dir: `{{openclaw_state_dir}}`{{/if}}
**Config Source:** {{config_source}}
**Environment:** {{os}} | User: {{user}} | Host: {{hostname}}
**ClawSafe Version:** 1.1.0

---

## Risk Summary

| Severity | Count | Indicator |
|----------|-------|-----------|
| 🔴 Critical | {{critical_count}} | Immediate action required |
| 🟠 High | {{high_count}} | Should be fixed before production |
| 🟡 Medium | {{medium_count}} | Recommended to fix |
| 🟢 Low | {{low_count}} | Consider improving |
| ℹ️ Info | {{info_count}} | For awareness |

**Total findings: {{total_count}}**

---

## Detailed Findings

### 🐾 OpenClaw Configuration

> Audit of the auto-discovered OpenClaw configuration and runtime environment.
> Discovery method: {{discovery_method}} | Config: `{{config_source}}`
> Reference: [OpenClaw Security Docs](https://docs.openclaw.ai/gateway/security)

{{#each openclaw_findings}}
#### [{{severity_icon}} {{severity}}] {{title}}

- **Check ID:** {{check_id}}
- **Location:** `{{location}}`
- **Detail:** {{detail}}
- **Suggestion:** {{suggestion}}
{{#if config_snippet}}
- **Recommended config:**
  ```json5
  {{config_snippet}}
  ```
{{/if}}

{{/each}}

### 🔒 Environment Configuration

{{#each env_findings}}
#### [{{severity_icon}} {{severity}}] {{title}}

- **Check ID:** {{check_id}}
- **Location:** `{{location}}`
- **Detail:** {{detail}}
- **Suggestion:** {{suggestion}}

{{/each}}

### 📁 File System Security

{{#each fs_findings}}
#### [{{severity_icon}} {{severity}}] {{title}}

- **Check ID:** {{check_id}}
- **Location:** `{{location}}`
- **Detail:** {{detail}}
- **Suggestion:** {{suggestion}}

{{/each}}

### 🌐 Network Exposure

{{#each net_findings}}
#### [{{severity_icon}} {{severity}}] {{title}}

- **Check ID:** {{check_id}}
- **Location:** `{{location}}`
- **Detail:** {{detail}}
- **Suggestion:** {{suggestion}}

{{/each}}

### 📦 Dependency Security

{{#each dep_findings}}
#### [{{severity_icon}} {{severity}}] {{title}}

- **Check ID:** {{check_id}}
- **Location:** `{{location}}`
- **Detail:** {{detail}}
- **Suggestion:** {{suggestion}}

{{/each}}

---

## Checks Performed

| Category | Script | Status |
|----------|--------|--------|
| OpenClaw Config | check_openclaw.sh | {{openclaw_status}} |
| Environment Config | check_env.sh | {{env_status}} |
| File System | check_files.sh | {{fs_status}} |
| Network Exposure | check_network.sh | {{net_status}} |
| Dependencies | check_deps.sh | {{deps_status}} |

## Scope Limitations

- Log file scanning limited to last 1000 lines per file
- Temp file scanning limited to files modified within last 24 hours
- CVE detection requires `pip-audit` or `npm audit` to be available
- Network port detection may require elevated privileges
- OpenClaw config parsing uses pattern matching (not a full JSON5 parser); deeply nested or unusual configs may produce false negatives
- {{additional_limitations}}

## Complementary Tools

For a more comprehensive assessment, also run:
- `openclaw security audit` — OpenClaw's built-in security checker
- `openclaw doctor --fix` — auto-fix common configuration issues

---

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
⚠️  This report is for reference only and
    cannot replace a professional security
    audit.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```
