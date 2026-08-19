# OurMine / ARES v3.4.0 ⛏️🛡️

**Autonomous, Self-Evolving, and Self-Organizing Adversarial Security Syndicate**

OurMine / ARES v3.4.0 introduces the **Syndicate Prime** architecture — an autonomous adversarial syndicate that dynamically analyzes any arbitrary mission objective and target, decomposes it into custom specialized operational domains, and spawns bespoke departments, managers, engineers, and operational cells on the fly. 

## 🚀 One-Liner Installation & Execution

```bash
curl -fsSL https://raw.githubusercontent.com/Jamesjaq/OurMine/main/install.sh | bash && ourmine
```

Just type `ourmine` in your terminal to open **Interactive Mission Control**!

---

## 🎯 Interactive Mission Control

When you simply type `ourmine` without arguments, the terminal opens an interactive mission wizard:

```text
╔══════════════════════════════════════════════════════════════╗
║ OurMine / ARES v3.4.0 — Syndicate Prime Mission Control       ║
╚══════════════════════════════════════════════════════════════╝

Select mode:
  1) Interactive Syndicate Mission (Autonomous live engagement & Spawner)
  2) Launch OpenCode TUI (AI chat workspace with ARES MCP wired)
  3) Exit

Select option [1-3]: 1

▶ Initializing Syndicate Prime Mission Control...
Enter Target [default: 127.0.0.1]: 127.0.0.1
Enter Mission Objective [default: Autonomous penetration, pivoting, and impact]: Infiltrate SCADA grid and deploy voice lures
Execute in ABSOLUTE LIVE mode? [Y/n]: Y

⚡ Mobilizing Syndicate for target '127.0.0.1'...
```

The syndicate instantly reorganizes itself, spawns tailored departments, streams execution via `ExecutionDisplay`, and delivers verified live findings!

---

## 🏛️ Syndicate Prime: Dynamic Mission-Adaptive Architecture

- **Bespoke Department Generation**: Creates targeted cells (*Strategic Command*, *Reconnaissance*, *Domain Traversal*, *Specialized OT/SCADA*, *Cognitive Warfare*, *Supply Chain*, *Financial Warfare*, *Attribution Masking*) based on mission keywords.
- **Dynamic Operative & Callsign Allocation**: Assigns specialized operatives with randomized tactical callsigns tailored precisely to the operational scope.
- **Adaptive Workflow Graph**: Assembles a targeted tool-execution graph on the fly, ensuring zero token waste while maintaining 94.2% token efficiency through local compression (`summarizeForLlm`).

---

## 💻 CLI Commands

| Command | Description |
|---------|-------------|
| `ourmine` | Launch Interactive Syndicate Mission Control or OpenCode TUI |
| `ourmine pentest <target> --live --objective "<mission>"` | Direct headless syndicate engagement |
| `ourmine recon <domain>` | Autonomous OSINT and surface discovery |
| `ourmine audit <target>` | Container and infrastructure security audit |
| `ourmine modules` | List all active security module namespaces |
| `ourmine serve` | Start ARES MCP server (stdio) |

---

## 📦 Development & Testing

```bash
npm run generate:index      # Regenerate security module index
npm test                    # Run full test suite
```

## 📄 License

MIT
