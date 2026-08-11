#!/usr/bin/env bash
# OurMine — one-line uninstaller (curl -fsSL .../uninstall.sh | bash)
set -euo pipefail

INSTALL_DIR="${OURMINE_INSTALL_DIR:-${HOME}/.ourmine}"
PURGE_CONFIG=0

for arg in "$@"; do
  case "$arg" in
    --purge-config) PURGE_CONFIG=1 ;;
    -h|--help)
      echo "Usage: uninstall.sh [--purge-config]"
      echo "  --purge-config  Remove OurMine MCP, agent, and TUI plugin from ~/.config/opencode"
      exit 0
      ;;
  esac
done

echo -e "\033[38;5;208m⛏  OurMine\033[0m — uninstalling"

if command -v npm >/dev/null 2>&1; then
  echo "Removing global ourmine CLI link..."
  npm unlink -g ourmine 2>/dev/null || npm rm -g ourmine 2>/dev/null || true
fi

if [ -d "${INSTALL_DIR}" ]; then
  echo "Removing ${INSTALL_DIR}..."
  rm -rf "${INSTALL_DIR}"
else
  echo "No install dir at ${INSTALL_DIR} (skipped)."
fi

if [ "${PURGE_CONFIG}" = "1" ]; then
  echo "Purging OurMine entries from OpenCode config..."
  node <<'NODE'
const fs = require("node:fs")
const os = require("node:os")
const path = require("node:path")

const configDir = path.join(process.env.XDG_CONFIG_HOME || path.join(os.homedir(), ".config"), "opencode")
const marker = "<!-- ourmine-ares-v1 -->"
const brandSuffix = "ourmine-brand.tsx"

function readJson(file) {
  try { return JSON.parse(fs.readFileSync(file, "utf8")) } catch { return null }
}

function writeJson(file, data) {
  if (!data || !Object.keys(data).length) {
    try { fs.unlinkSync(file) } catch {}
    return
  }
  fs.mkdirSync(path.dirname(file), { recursive: true })
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + "\n")
}

function stripOurMine(obj) {
  if (!obj || typeof obj !== "object") return obj
  if (obj.mcp?.ares) delete obj.mcp.ares
  if (obj.mcp && !Object.keys(obj.mcp).length) delete obj.mcp
  if (obj.default_agent === "pentest") delete obj.default_agent
  if (obj.mcp?.["ourmine-ares"]) delete obj.mcp["ourmine-ares"]
  if (obj.mcp?.["ourmine-ares-live"]) delete obj.mcp["ourmine-ares-live"]
  return obj
}

for (const name of ["opencode.json", "config.json"]) {
  const file = path.join(configDir, name)
  const data = readJson(file)
  if (!data) continue
  writeJson(file, stripOurMine(data))
}

const tuiFile = path.join(configDir, "tui.json")
const tui = readJson(tuiFile)
if (tui?.plugin && Array.isArray(tui.plugin)) {
  tui.plugin = tui.plugin.filter((p) => !String(p).includes(brandSuffix))
  if (!tui.plugin.length) delete tui.plugin
  writeJson(tuiFile, Object.keys(tui).length ? tui : null)
}

const agentFile = path.join(configDir, "agent", "pentest.md")
try {
  const text = fs.readFileSync(agentFile, "utf8")
  if (text.includes(marker)) fs.unlinkSync(agentFile)
} catch {}

console.log("OpenCode config purged.")
NODE
fi

echo -e "\n\033[32m✔ OurMine removed.\033[0m"
if [ "${PURGE_CONFIG}" != "1" ]; then
  echo "OpenCode config left intact. To remove ARES MCP + pentest agent wiring:"
  echo "  curl -fsSL https://raw.githubusercontent.com/Jamesjaq/OurMine/main/uninstall.sh | bash -s -- --purge-config"
fi
echo "OpenCode itself was not removed."
