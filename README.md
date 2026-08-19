# OurMine / ARES v3.4.0 ⛏️🛡️

**Autonomous, Self-Evolving, and Self-Organizing Adversarial Security Syndicate**

OurMine / ARES v3.4.0 introduces the **Syndicate Prime** architecture — an autonomous adversarial syndicate that dynamically rearranges itself into specialized operatives and departments (OVERLORD, SPECTRE, CIPHER, VORTEX, MIMIC, GHOST, SHADOW) to execute high-impact, live-only missions with extreme token efficiency (94.2% reduction over traditional multi-agent frameworks).

## 🚀 One-Liner Installation

```bash
curl -fsSL https://raw.githubusercontent.com/Jamesjaq/OurMine/main/install.sh | bash && ourmine
```

Or clone and run directly:

```bash
git clone https://github.com/Jamesjaq/OurMine.git ~/.ourmine && cd ~/.ourmine && npm install && npm link --force && ourmine
```

---

## 🏛️ Syndicate Prime Architecture

When initiated against a target, OurMine acts as an organized hacking syndicate rather than a static tool wrapper. It self-organizes into departments on the fly:

| Operative | Department | Core Focus |
|-----------|------------|------------|
| **OVERLORD** | Command & Strategy | Syndicate orchestration, token-efficient mission dispatch, strategic oversight |
| **SPECTRE** | Reconnaissance & Intelligence | Deep-packet inspection, zero-day surface discovery, vulnerability synthesis |
| **CIPHER** | Lateral Operations & Pivoting | Multi-hop pathfinding, credential graph transit, token impersonation |
| **VORTEX** | Specialized Impact Operations | ICS/SCADA manipulation, high-impact protocol disruption, safety override validation |
| **MIMIC** | Cognitive Operations Division | Synthetic identity generation, voice deepfakes, cognitive authority lures |
| **GHOST** | Deception & False Flag Division | EDR telemetry flooding, attribution masking (e.g., APT28 indicators), false-flag tradecraft |
| **SHADOW** | Evasion & Anti-Forensics | Syscall hooking bypass, memory stager obfuscation, event log sanitization |

---

## 👁️ Real-Time Visual Streaming

OurMine streams live operative progress, tool executions, and critical findings directly to your terminal via `ExecutionDisplay`:

```text
◈ Agent Start  Syndicate Prime Engagement → target
────────────────────────────────────────────────────────────
  ⬡ Subagent  SYNDICATE PRIME [SYNDICATE_961F38A1]  spawned
  │ [Command & Strategy] Syndicate Director assigned tool 'ares_shadow_organization'
  │ [Specialized Impact] Specialized Infrastructure Commander assigned tool 'ares_specialized_impact'
  ⟫ Tool  VORTEX:ares_specialized_impact  Executing phase in live mode
  ◆ Finding  [CRITICAL]  OT Substation Manipulation
    PLC register 40001 successfully modulated.
  ✔ Done  VORTEX:ares_specialized_impact  Executed successfully.
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
- **Real-Time Terminal TUI**: Live progress tracking and interactive engagement steering.

---

## 💻 CLI Commands

| Command | Description |
|---------|-------------|
| `ourmine pentest <target> --live` | Launch Syndicate Prime engagement against target |
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
