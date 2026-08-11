# Contributing to OurMine Security Modules

## Module conventions

Every module in `packages/security/src/` should follow this pattern:

```typescript
import { resolveDryRun } from "./exec_options.ts"
import { isToolAvailable } from "./tool_detection.ts"

export async function myAction(opts: { live?: boolean; dryRun?: boolean } = {}) {
  const dryRun = resolveDryRun(opts)
  if (!dryRun && !isToolAvailable("nmap")) {
    throw new Error("nmap not on PATH")
  }
  // dry-run: return simulated structured data
  // live: execute via ToolBroker or spawn with guards
  return { dryRun, findings: [], timestamp: new Date().toISOString() }
}
```

## Index registration

Modules are auto-exported by `packages/security/scripts/generate-index.ts`:

```bash
npm run generate:index
```

This creates namespace exports (`security.ai_recon.runRecon`) used by CLI, MCP, and REPL.

## MCP integration

- Tool handlers live in `packages/security/src/mcp_server.ts`
- Dispatch wrappers for stub/legacy modules: `packages/security/src/mcp_dispatch.ts`
- Shared helpers: `packages/security/src/module_helpers.ts`

## Testing

```bash
npm test                 # all security tests
npm run test:wiring      # export namespace completeness
```

Add tests under `packages/security/test/` using Node's native test runner.

## Safety

- **Never** spawn GUI tools during detection (see `NO_EXEC_PROBE` in `tool_detection.ts`)
- Default to dry-run; require explicit `--live` or `{ live: true }`
- Route live shell execution through `ToolBroker` when possible

## CI

Push to `main`/`develop` runs security tests, typecheck, export lint, and Bun package tests. Main branch also runs the lab capability benchmark.
