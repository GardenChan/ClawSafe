# 🛡️ ClawSafe

**AI Agent 运行环境安全自检工具，专为 [OpenClaw Gateway](https://docs.openclaw.ai) 打造。**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[📖 English](README.md)

ClawSafe 是一个 OpenClaw Skill，通过一系列跨平台 Shell 脚本对 AI Agent 的运行环境进行安全审计，识别配置风险并生成分级报告。

```
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🔍 35 项安全检测
  🐾 16 项 OpenClaw 专属检测
  🖥️  支持 Linux / macOS / 容器
  🔒 只读检测，不修改任何文件
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

## ✨ 特性

- **零路径假设** — OpenClaw 安装路径通过多策略引擎动态发现（CLI / 环境变量 / 进程检查 / 文件搜索），从不硬编码
- **35 项安全检测** — 覆盖 OpenClaw 配置、环境变量、文件系统、网络暴露、依赖安全 5 大类
- **只读安全** — 所有检测脚本只读取信息，不修改任何文件或配置
- **敏感数据脱敏** — 发现的密钥/令牌仅展示前 4 个字符
- **JSON Lines 输出** — 结构化输出，便于集成和自动化处理
- **跨平台** — 支持 Linux、macOS 和容器环境

## 📦 安装

### 方式一：全局安装（推荐，所有 Agent 共享）

```bash
git clone https://github.com/GardenChan/ClawSafe.git ~/.openclaw/skills/clawsafe
```

> 如果你的 OpenClaw 状态目录不在默认位置：
> ```bash
> git clone https://github.com/GardenChan/ClawSafe.git "$OPENCLAW_STATE_DIR/skills/clawsafe"
> ```

### 方式二：工作区安装（仅当前项目可用，优先级最高）

```bash
cd /your/project/workspace
mkdir -p skills
git clone https://github.com/GardenChan/ClawSafe.git skills/clawsafe
```

### 方式三：自定义目录

克隆到任意位置，然后在 `openclaw.json` 中配置：

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

安装后 OpenClaw 会自动检测并加载 Skill，无需重启。

## 🚀 使用

### 通过 OpenClaw Agent 对话触发

安装完成后，直接在 Agent 对话中说：

> "帮我做一次安全自检"
>
> "run a security scan"
>
> "检查 OpenClaw 安全配置"

Agent 会自动调用 ClawSafe 执行检测并生成报告。

### 直接运行脚本

你也可以脱离 OpenClaw 直接运行：

```bash
# 全量扫描（当前目录）
bash scripts/run_all.sh

# 全量扫描（指定目录）
bash scripts/run_all.sh /path/to/project

# 仅检测 OpenClaw 配置（自动发现路径）
bash scripts/check_openclaw.sh

# 指定 OpenClaw 状态目录
bash scripts/check_openclaw.sh /custom/openclaw/state

# 通过环境变量指定
OPENCLAW_STATE_DIR="/custom/path" bash scripts/check_openclaw.sh

# 单独运行某个模块
bash scripts/check_env.sh /path/to/project
bash scripts/check_files.sh /path/to/project
bash scripts/check_network.sh /path/to/project
bash scripts/check_deps.sh /path/to/project
```

## 🔍 检测项总览

### 🐾 OpenClaw 配置审计（16 项）

| ID | 检测内容 | 严重级别 |
|----|---------|---------|
| OC000 | 发现报告（使用了哪种发现策略、检查了哪些路径） | INFO |
| OC001 | 状态目录 / 配置文件 / 认证凭据文件权限 | HIGH |
| OC002 | Gateway 绑定非回环地址 / 缺少认证 / 弱令牌 | CRITICAL ~ MEDIUM |
| OC003 | DM/群组策略过于开放 / 通配符 allowFrom | HIGH ~ MEDIUM |
| OC004 | 沙箱模式关闭或配置异常 / 策略漂移 | HIGH ~ LOW |
| OC005 | 提权工具启用 / 无工具拒绝列表 | HIGH ~ MEDIUM |
| OC006 | Skill API Key 硬编码 / 第三方 Skill 风险 | HIGH ~ INFO |
| OC007 | Webhook 缺少令牌 / 允许不安全内容 | CRITICAL ~ HIGH |
| OC008 | Cron 工具对 Agent 可用 | MEDIUM |
| OC009 | 敏感日志脱敏未启用 | HIGH ~ LOW |
| OC010 | mDNS 广播内部信息 | MEDIUM |
| OC011 | 多 Agent 隔离问题（共享 agentDir/workspace） | CRITICAL ~ MEDIUM |
| OC012 | 会话存储目录 / 文件权限 | HIGH ~ MEDIUM |
| OC013 | 浏览器 SSRF 允许私有网络访问 | MEDIUM |
| OC014 | 插件 Prompt 注入 / 无插件白名单 | HIGH ~ MEDIUM |
| OC015 | OpenClaw .env 文件权限 | HIGH |

### 🔒 环境配置（ENV）

API Key 硬编码、`.env` 被 Git 追踪、文件权限不当、使用默认值等。

### 📁 文件系统（FS）

敏感文件暴露、系统目录写入权限、日志泄露、临时文件残留、项目中的密钥文件等。

### 🌐 网络暴露（NET）

端口绑定、HTTPS 配置、CORS 策略、公共 IP 暴露等。

### 📦 依赖安全（DEP）

版本未固定、缺少 Lock 文件、CVE 漏洞审计、Docker 镜像来源等。

> 📋 完整检测清单及详细说明见 [`references/checklist.md`](references/checklist.md)

## 🧭 OpenClaw 路径发现机制

ClawSafe **绝不假设任何固定路径**。`check_openclaw.sh` 通过多策略引擎按优先级动态发现：

| 优先级 | 策略 | 说明 |
|--------|------|------|
| 1 | 显式参数 | 用户直接传入路径 |
| 2 | `openclaw` CLI | 查询运行中的 Gateway 获取实际配置（最可靠） |
| 3 | `OPENCLAW_CONFIG_PATH` 环境变量 | 直接指向配置文件 |
| 4 | `OPENCLAW_STATE_DIR` 环境变量 | 指向状态目录 |
| 5 | `OPENCLAW_HOME` 环境变量 | 替代 `$HOME` 做路径解析 |
| 6 | 运行进程检查 | 从进程环境变量/命令行读取 |
| 7 | 文件系统搜索 | `$HOME` 下限深搜索（兜底） |

发现结果始终作为 `OC000` 输出，确保用户可以验证检查了什么。

## 📊 输出格式

每个检测项输出一条 JSON Line：

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

报告模板见 [`assets/report_template.md`](assets/report_template.md)。

## 📂 项目结构

```
ClawSafe/
├── SKILL.md                    # OpenClaw Skill 定义文件（入口）
├── README.md                   # 英文文档
├── README.zh-CN.md             # 中文文档（本文件）
├── LICENSE                     # MIT License
├── scripts/
│   ├── run_all.sh              # 全量扫描入口
│   ├── check_openclaw.sh       # OpenClaw 配置审计（含动态发现引擎）
│   ├── check_env.sh            # 环境变量检测
│   ├── check_files.sh          # 文件系统检测
│   ├── check_network.sh        # 网络暴露检测
│   ├── check_deps.sh           # 依赖安全检测
│   └── utils.sh                # 公共工具函数
├── assets/
│   └── report_template.md      # 报告模板
└── references/
    └── checklist.md            # 完整检测清单及详细说明
```

## 🤝 配合使用

ClawSafe 是补充性工具，建议同时使用 OpenClaw 内置命令：

```bash
# OpenClaw 内置安全审计
openclaw security audit

# 自动修复常见配置问题
openclaw doctor --fix
```

## ⚠️ 免责声明

ClawSafe 是一个辅助性安全自检工具，**不能替代专业安全审计**。检测由 Agent 在自身环境中执行，如果环境已被攻陷，结果可能不可信。建议对关键发现进行独立验证。

## 📄 License

[MIT](LICENSE) © garden
