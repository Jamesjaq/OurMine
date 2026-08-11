# OurMine ⛏️

**Autonomous AI Security & Developer Platform**

Built on **OpenCode** with the **ARES Security Suite** — 115+ security modules for recon, auditing, pentest automation, MITRE ATT&CK TTPs, validation pipelines, and OPSEC-safe dry-run defaults.

## Quick Start

```bash
git clone https://github.com/Jamesjaq/OurMine.git
cd OurMine
npm install
npm link --force

ourmine                  # launches OpenCode TUI — ARES wired automatically
```

That's it. Pick a model with `/model`, tell the agent your target, and it goes to work.

On first launch, OurMine auto-wires:
- **ARES MCP server** (`ares`) — 50+ offensive security tools
- **`pentest` agent** as default — APT-level autonomous engagement
- **Live mode on Kali** — real execution, no simulations

### Example session

```
/model                          # browse and pick any model you have keys for
Target is 10.10.10.5, full pentest
```

Or use the slash command:

```
/pentest 10.10.10.5
```

## Security CLI (headless)

These run outside the TUI for scripting and automation:

| Command | Description |
|---------|-------------|
| `ourmine recon <domain>` | AI-driven OSINT + subdomain recon |
| `ourmine audit <target>` | Container / cloud security audit |
| `ourmine pentest <target>` | Autonomous PentestGPT attack plan |
| `ourmine agent <target>` | LLM-driven pentest agent (no TUI) |
| `ourmine yara <path>` | YARA rulepack scan |
| `ourmine toolcheck` | Security tool availability report |
| `ourmine serve` | Start ARES MCP server (stdio) |
| `ourmine modules` | List all module namespaces |

Flags: `--live` (real execution), `--dry-run` (force simulation), `--require-live` (fail if tools missing).

On Kali Linux, live mode is enabled automatically.

## Architecture

```
ourmine (no args)  →  bootstrap ARES MCP + pentest agent  →  OpenCode TUI
                              ↓
                     ares_* MCP tools (50+)
                              ↓
                     PentestAgent closed loop (graph → tools → validation)
```

| Component | Path | Description |
|-----------|------|-------------|
| OpenCode core | `packages/opencode/` | TUI, sessions, model browsing, agent loop |
| Security engine | `packages/security/src/` | 115+ ARES modules |
| MCP server | `packages/security/src/mcp_server.ts` | Exposes ARES tools to LLM agents |
| Bootstrap | `packages/security/src/opencode_bootstrap.ts` | Auto-wires MCP + agent on launch |
| CLI | `bin/ourmine.ts` | TUI launcher + headless security commands |

Config written on launch:
- Global: `~/.config/opencode/opencode.json` (MCP + default agent)
- Project: `.opencode/agent/pentest.md`, `.opencode/command/pentest.md`

## Development

```bash
npm run generate:index   # regenerate packages/security/src/index.ts
npm test                 # 79 security tests (Node native runner)
npm run test:wiring      # namespace export integration tests
npm run capability:benchmark  # lab benchmark (requires tools + port 8080 target)
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for module authoring conventions.

## License

MIT
