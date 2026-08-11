# OurMine ⛏️

**Autonomous AI Security & Developer Platform**

Built on **OpenCode** with the **ARES Security Suite** — 115+ security modules for recon, auditing, pentest automation, MITRE ATT&CK TTPs, validation pipelines, and OPSEC-safe dry-run defaults.

## Quick Start

```bash
git clone https://github.com/Jamesjaq/OurMine.git
cd OurMine
npm install
npm link --force

ourmine --help
ourmine modules          # list all ARES namespaces
ourmine toolcheck        # check installed security tools
ourmine recon example.com
ourmine audit target.local
ourmine serve            # MCP server for LLM agents
```

## Security Commands

| Command | Description |
|---------|-------------|
| `ourmine recon <domain>` | AI-driven OSINT + subdomain recon |
| `ourmine audit <target>` | Container / cloud security audit |
| `ourmine pentest <target>` | Autonomous PentestGPT attack plan |
| `ourmine agent <target>` | LLM-driven pentest agent |
| `ourmine yara <path>` | YARA rulepack scan |
| `ourmine toolcheck` | Security tool availability report |
| `ourmine serve` | Start ARES MCP server (stdio) |
| `ourmine modules` | List all module namespaces |

Use `--live` to enable real execution (dry-run is default).

## Architecture

| Component | Package | Description |
|-----------|---------|-------------|
| OpenCode core | `@opencode-ai/core` | Session store, agent loop, IDE foundation |
| Security engine | `@ourmine/security` | 115 ARES modules under `packages/security/src/` |
| CLI | `bin/ourmine.ts` | Security commands + OpenCode delegation |
| Lab benchmark | `lab/benchmark_runner.ts` | End-to-end capability proof against local target |

## Development

```bash
npm run generate:index   # regenerate packages/security/src/index.ts
npm test                 # 71+ security tests (Node native runner)
npm run test:wiring      # namespace export integration tests
npm run capability:benchmark  # lab benchmark (requires tools + port 8080 target)
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for module authoring conventions.

## License

MIT
