# OurMine ⛏️

**Autonomous AI Security & Developer Platform**

Built natively on **OpenCode** as the base foundation, infused with the **ARES Security Suite** (reconnaissance, vulnerability auditing, adversary emulation, MITRE ATT&CK TTPs, HITL safety gates, YARA scanning, and OPSEC verification).

---

## Quick Start

```bash
# One-line installer:
curl -fsSL https://raw.githubusercontent.com/Jamesjaq/OurMine/main/install.sh | bash

# Or locally:
cd OurMine
npm install
npm link --force

# Launch
ourmine status
ourmine --help
ourmine tui
```

## Architecture

| Component | Description |
| :--- | :--- |
| **`@ourmine/agent`** | OpenCode native agent turn loop (`while-needs-continuation`) |
| **`@ourmine/core`** | Session store, context epoch engine, & ARES state machine |
| **`@ourmine/tui`** | Solid-JS / OpenTUI interactive terminal interface |
| **`@ourmine/devtools`** | LSP client, PTY terminal supervisor, Git worktree manager, code patcher |
| **`@ourmine/security`** | ARES ATT&CK tool corpus (YARA, C2, AD engine, Cloud, Evasion, Identity PRT) |
| **`@ourmine/gateway`** | REST + WebSocket RPC server daemon |
| **`db/ares2.db`** | Seeded SQLite database with MITRE ATT&CK TTPs & YARA rulepacks |

## License

MIT
