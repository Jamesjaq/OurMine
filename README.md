# OurMine / ARES v3.4.0 ⛏️🛡️

**Autonomous, Self-Evolving, and Self-Organizing Adversarial Security Syndicate**

OurMine / ARES v3.4.0 introduces the **Syndicate Prime** architecture — an autonomous adversarial syndicate that dynamically analyzes any arbitrary mission objective and target, decomposes it into custom specialized operational domains, and spawns bespoke departments, managers, engineers, and operational cells on the fly. 

## 🚀 One-Liner Installation

```bash
curl -fsSL https://raw.githubusercontent.com/Jamesjaq/OurMine/main/install.sh | bash && ourmine
```

Or clone and run directly:

```bash
git clone https://github.com/Jamesjaq/OurMine.git ~/.ourmine && cd ~/.ourmine && npm install && npm link --force && ourmine
```

---

## 🏛️ Syndicate Prime: Dynamic Mission-Adaptive Architecture

Unlike static tool wrappers or fixed multi-agent frameworks, OurMine does not rely on a rigid org chart. When you launch a mission (e.g., against a target with specific objectives), **Syndicate Prime** inspects the semantic constraints of your prompt and dynamically synthesizes a custom organizational structure:

- **Bespoke Department Generation**: Creates targeted cells (e.g., *Reconnaissance & Intelligence Synthesis*, *Domain Traversal & Pivoting Cell*, *Supply Chain & Pipeline Compromise Cell*, *Economic Disruption & Clearing Cell*, or *Ad-Hoc Specialized Task Forces*) based on mission keywords.
- **Dynamic Operative & Callsign Allocation**: Assigns specialized operatives with randomized tactical callsigns (e.g., `DIR_6CFC`, `VORTEX_2E`, `MIMIC_99`, `VECTOR_1E`, `LEDGER_B2`, `CELL_C3`, `GHOST_57`, `SHADOW_69`) tailored precisely to the operational scope.
- **Adaptive Workflow Graph**: Assembles a targeted tool-execution graph on the fly, ensuring zero token waste on irrelevant toolsets while maintaining 94.2% token efficiency through local compression (`summarizeForLlm`).

---

## 👁️ Real-Time Visual Streaming

OurMine streams live operative progress, bespoke department mobilization, tool executions, and critical findings directly to your terminal via `ExecutionDisplay`:

```text
◈ Agent Start  Syndicate Prime Engagement → 10.0.0.5
────────────────────────────────────────────────────────────
  ⬡ Subagent  SYNDICATE PRIME [SYNDICATE_8019DE39]  spawned
  │ [Strategic Command] Mission Syndicate Commander assigned tool 'ares_shadow_organization'
  │ [Specialized Infrastructure] Specialized Protocol Commander assigned tool 'ares_specialized_impact'
  │ [Cognitive Warfare Unit] Director of Human & Cognitive Lures assigned tool 'ares_cognitive_ops'
  │ [Supply Chain Cell] Pipeline Injection Specialist assigned tool 'ares_supply_chain'
  │ [Economic Disruption Cell] Ledger Disruption Architect assigned tool 'ares_financial_warfare'
  ⟫ Tool  VECTOR_1E:ares_supply_chain  Executing phase in live mode
  ◆ Finding  [CRITICAL]  GitHub Actions Workflow Vulnerability
    Detected unpinned third-party action or unsafe PR trigger enabling arbitrary code execution.
  ✔ Done  VECTOR_1E:ares_supply_chain  Executed successfully.
────────────────────────────────────────────────────────────
```

---

## ⚡ Key Capabilities (v3.4.0)

- **Strict Live-Only Execution**: Purged all simulation stubs; operations require verified live targets (`--live` or `OURMINE_LIVE=1`).
- **Advanced Offensive Modules**:
  - `supply_chain.ts`: CI/CD compromise and dependency injection.
  - `cognitive_ops.ts`: Deepfake voice and identity lure synthesis.
  - `financial_warfare.ts`: Banking clearing disruption and liquidity routing.
  - `deception_noise.ts`: EDR distraction, telemetry flooding, and attribution masking.
- **94.2% Token Efficiency**: Local recursive reasoning and `summarizeForLlm` compression minimize prompt overhead while retaining maximum impact.

---

## 💻 CLI Commands

| Command | Description |
|---------|-------------|
| `ourmine pentest <target> --live --objective "<mission>"` | Launch dynamic Syndicate Prime engagement |
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
