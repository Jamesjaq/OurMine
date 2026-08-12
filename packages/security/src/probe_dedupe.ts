/**
 * @module probe_dedupe
 * 5-minute TTL fingerprint cache for live OT/HTTP probes (extends VALIDATION_CACHE pattern).
 */
const PROBE_CACHE = new Map<string, { result: unknown; ts: number }>()
export const PROBE_CACHE_TTL_MS = 5 * 60 * 1_000

export function probeFingerprint(kind: string, target: string, extra?: string): string {
  return `${kind}|${target}|${extra ?? ""}`
}

export function getCachedProbe<T>(fingerprint: string): T | null {
  const entry = PROBE_CACHE.get(fingerprint)
  if (!entry) return null
  if (Date.now() - entry.ts >= PROBE_CACHE_TTL_MS) {
    PROBE_CACHE.delete(fingerprint)
    return null
  }
  return entry.result as T
}

export function setCachedProbe(fingerprint: string, result: unknown): void {
  PROBE_CACHE.set(fingerprint, { result, ts: Date.now() })
}

/** Run probe fn once per fingerprint within TTL; returns cached result on hit. */
export async function dedupeProbe<T>(
  fingerprint: string,
  fn: () => Promise<T>,
): Promise<{ result: T; cached: boolean }> {
  const hit = getCachedProbe<T>(fingerprint)
  if (hit != null) return { result: hit, cached: true }
  const result = await fn()
  setCachedProbe(fingerprint, result)
  return { result, cached: false }
}

export function clearProbeCache(): void {
  PROBE_CACHE.clear()
}

export default { probeFingerprint, getCachedProbe, setCachedProbe, dedupeProbe, clearProbeCache, PROBE_CACHE_TTL_MS }
