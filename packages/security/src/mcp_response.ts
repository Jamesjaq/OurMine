/**
 * @module mcp_response
 * MCP tool response formatting, throttling policy, and payload normalization.
 */
import { compactToolOutput, isEfficientMode } from "./mcp_efficiency.ts"
import { writeArtifact, shouldStoreAsArtifact, artifactPreview } from "./mcp_artifacts.ts"
import type { PlanAction } from "./pentest_plan_builder.ts"
import { EngagementMemory } from "./engagement_memory.ts"
import {
  buildEngagementDelta,
  compressEngagementPayload,
  snapshotFromPayload,
} from "./semantic_compression.ts"

/** Meta/read-only tools skip OPSEC pacing (avoids ~1s tax per discovery call). */
export const THROTTLE_EXEMPT_TOOLS = new Set([
  "ares_tool_search",
  "ares_tool_call",
  "ares_skills_list",
  "ares_pentest_plan",
  "ares_engagement_slice",
  "ares_engagement_continue",
  "ares_artifact_get",
  "ares_opsec_throttle",
  "ares_intel_feed",
  "ares_threat_intel",
  "ares_agent_resilience",
  "ares_engagement_watch",
  "ares_proof_export",
])

const ENGAGEMENT_TOOLS = new Set(["ares_engagement_slice", "ares_engagement_continue"])

export function shouldThrottleTool(toolName: string): boolean {
  return !THROTTLE_EXEMPT_TOOLS.has(toolName)
}

function tryParseJson(value: unknown): Record<string, unknown> | null {
  if (typeof value !== "string") return null
  try {
    const parsed = JSON.parse(value)
    return parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null
  } catch {
    return null
  }
}

/** Flatten bridged `{ output: "{...json...}" }` shapes into one object. */
export function normalizeToolPayload(payload: unknown): Record<string, unknown> {
  if (payload == null) return {}
  if (typeof payload !== "object" || Array.isArray(payload)) {
    return { summary: String(payload).slice(0, 200) }
  }

  const p = { ...(payload as Record<string, unknown>) }

  if (typeof p.output === "string") {
    const nested = tryParseJson(p.output)
    if (nested) {
      const { output: _drop, ...rest } = p
      return { ...rest, ...nested }
    }
  }

  return p
}

function compactNextActions(actions: unknown): Array<{ s: number; t: string; a: Record<string, string> }> {
  if (!Array.isArray(actions)) return []
  return (actions as PlanAction[]).slice(0, 4).map((a) => ({
    s: a.step,
    t: a.tool,
    a: a.args ?? {},
  }))
}

/** Ultra-compact engagement slice response (target ≤400 bytes). Full detail in artifact. */
export function compactEngagementResponse(
  payload: Record<string, unknown>,
  maxLen = 400,
): string {
  const { compressed, hostRegistry, savedBytes } = compressEngagementPayload(payload)
  if (hostRegistry) {
    writeArtifact("host_registry", hostRegistry)
    compressed.hreg = true
  }

  const pr = compressed.phaseResult as Record<string, unknown> | undefined
  const compact: Record<string, unknown> = {
    s: String(compressed.summary ?? "").slice(0, 72),
    t: compressed.target,
    obj: compressed.objective,
    ph: pr?.phase,
    ok: pr ? `${pr.stepsOk ?? pr.succeeded}/${pr.stepCount ?? "?"}` : undefined,
    cf: Array.isArray(compressed.confirmed) ? compressed.confirmed.length : 0,
    cd: Array.isArray(compressed.candidates) ? compressed.candidates.length : 0,
    bk: Array.isArray(compressed.blockers) ? compressed.blockers.length : 0,
  }
  if (compressed.dryRun) compact.dry = true
  if (compressed.resumeToken) compact.rt = compressed.resumeToken
  if (compressed.recommendedNextPhase) compact.nxp = compressed.recommendedNextPhase
  if (typeof compressed.intelDigest === "string") compact.is = compressed.intelDigest.slice(0, 80)
  else if (typeof compressed.intelSnippet === "string") compact.is = compressed.intelSnippet.slice(0, 80)
  if (compressed.intelFromMemory) compact.im = true
  if (compressed.cacheHit) compact.ch = true
  if (typeof compressed.parallelProbes === "number" && compressed.parallelProbes > 0) {
    compact.pp = compressed.parallelProbes
  }

  const na = compactNextActions(compressed.graphNextActions)
  if (na.length) compact.na = na

  const artifactId = writeArtifact("engagement", compressed)
  compact.aid = artifactId
  if (savedBytes > 0) compact.saved = savedBytes

  let out = JSON.stringify(compact)
  if (out.length > maxLen) {
    compact.s = String(compact.s).slice(0, 48)
    compact.na = na.slice(0, 2).map(({ s, t }) => ({ s, t, a: {} }))
    out = JSON.stringify(compact)
  }
  if (out.length > maxLen) {
    compact.na = na.length ? [{ s: na[0]!.s, t: na[0]!.t, a: {} }] : []
    compact.aid = String(compact.aid).slice(-12)
    out = JSON.stringify(compact)
  }
  return out.length > maxLen ? out.slice(0, maxLen - 3) + "..." : out
}

/** Delta-only continue response — omits unchanged counters when prior snapshot exists. */
export function compactEngagementContinueResponse(
  payload: Record<string, unknown>,
  maxLen = 280,
): string {
  const target = String(payload.target ?? "")
  const token = String(payload.resumeToken ?? "")
  const memory = EngagementMemory.loadForTarget(target)
  const prev = memory.getSliceSnapshot(token)

  const { compressed, hostRegistry } = compressEngagementPayload(payload)
  if (hostRegistry) writeArtifact("host_registry", hostRegistry)

  const artifactId = writeArtifact("engagement", compressed)
  memory.saveSliceSnapshot(token, snapshotFromPayload(compressed))

  let body: Record<string, unknown>
  if (prev) {
    body = buildEngagementDelta(prev, compressed)
    body.rt = token
    body.aid = artifactId
    body.im = true
  } else {
    body = JSON.parse(compactEngagementResponse(compressed, maxLen)) as Record<string, unknown>
  }

  const na = compactNextActions(compressed.graphNextActions)
  if (na.length) body.na = na.slice(0, 2)

  let out = JSON.stringify(body)
  if (out.length > maxLen) {
    delete body.s
    delete body.na
    out = JSON.stringify(body)
  }
  if (out.length > maxLen) {
    body = { d: true, rt: token, aid: String(artifactId).slice(-12), ph: body.ph }
    out = JSON.stringify(body)
  }
  return out.length > maxLen ? out.slice(0, maxLen - 1) + "}" : out
}

/** Format any tool result for MCP text content (efficient + search modes). */
export function formatMcpToolResponse(payload: unknown, opts: { maxLen?: number; kind?: string } = {}): string {
  const normalized = normalizeToolPayload(payload)
  const kind = opts.kind ?? ""

  if (ENGAGEMENT_TOOLS.has(kind)) {
    if (kind === "ares_engagement_continue") {
      return compactEngagementContinueResponse(normalized, opts.maxLen ?? 280)
    }
    return compactEngagementResponse(normalized, opts.maxLen ?? 400)
  }

  const maxLen = opts.maxLen ?? (isEfficientMode() ? 1200 : 2500)

  if (shouldStoreAsArtifact(normalized, maxLen)) {
    const artifactId = writeArtifact(opts.kind ?? "mcp_tool", normalized)
    const compact = {
      summary: typeof normalized.summary === "string"
        ? normalized.summary.slice(0, 300)
        : "Large payload stored as artifact",
      artifactId,
      preview: artifactPreview(normalized),
    }
    return JSON.stringify(compact)
  }

  return compactToolOutput(normalized, maxLen)
}

/** Shape bridged module results for MCP (no nested JSON strings). */
export function flattenBridgedResult(result: {
  tool: string
  success: boolean
  dryRun: boolean
  output: string
}): Record<string, unknown> {
  const nested = tryParseJson(result.output)
  if (nested) {
    return {
      tool: result.tool,
      success: result.success,
      dryRun: result.dryRun,
      ...nested,
    }
  }
  return {
    tool: result.tool,
    success: result.success,
    dryRun: result.dryRun,
    summary: result.output.slice(0, 400),
  }
}

export default {
  THROTTLE_EXEMPT_TOOLS,
  shouldThrottleTool,
  normalizeToolPayload,
  compactEngagementResponse,
  compactEngagementContinueResponse,
  formatMcpToolResponse,
  flattenBridgedResult,
}
