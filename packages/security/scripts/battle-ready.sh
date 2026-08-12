#!/usr/bin/env bash
# ARES battle-ready — source env and print operational status (start-and-go).
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_ROOT="$(cd "$PKG_DIR/../.." && pwd)"

ENV_FILE="$PKG_DIR/.env.local"
if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "$ENV_FILE"
  set +a
fi

export OURMINE_BATTLE_READY="${OURMINE_BATTLE_READY:-1}"
export OURMINE_LIVE="${OURMINE_LIVE:-1}"
export OURMINE_ROE_SIGNED="${OURMINE_ROE_SIGNED:-1}"
export OURMINE_PASSIVE_INTEL="${OURMINE_PASSIVE_INTEL:-1}"
export OURMINE_MCP_EFFICIENT="${OURMINE_MCP_EFFICIENT:-1}"
export OURMINE_INTEL_REFRESH="${OURMINE_INTEL_REFRESH:-1}"

cd "$REPO_ROOT"

node --experimental-strip-types -e "
import { isBattleReady, isKaliLinux, resolveLiveMode } from './packages/security/src/exec_options.ts'
import { isRoeSigned } from './packages/security/src/roe_attestation.ts'
import { isPassiveIntelEnabled } from './packages/security/src/passive_intel.ts'
import { intelRefreshEnabled } from './packages/security/src/intel_autonomous.ts'

const on = (b) => b ? '\x1b[32mON\x1b[0m' : '\x1b[33mOFF\x1b[0m'
const hasShodan = Boolean(process.env.SHODAN_API_KEY)

console.log('')
console.log('\x1b[38;5;208m⛏️  OurMine ARES — Battle Ready\x1b[0m')
console.log('────────────────────────────────────')
console.log('  host        ', isKaliLinux() ? 'Kali Linux' : process.platform)
console.log('  live        ', on(resolveLiveMode()))
console.log('  battleReady ', on(isBattleReady()))
console.log('  roeSigned   ', on(isRoeSigned()))
console.log('  passiveIntel', on(isPassiveIntelEnabled()), hasShodan ? '(Shodan key set)' : '(no Shodan key)')
console.log('  intelRefresh', on(intelRefreshEnabled()))
console.log('  mcpEfficient', on(process.env.OURMINE_MCP_EFFICIENT === '1'))
console.log('')
console.log('Ready — give a target via Cursor MCP (ourmine-ares) or: ourmine')
console.log('Repo:', '$REPO_ROOT')
console.log('')
"
