/**
 * @module security/opsec_throttle
 * Operational Traffic Control & Pacing Engine
 * Controls execution timing, request pacing, and concurrency limits to maintain predictable assessment behavior.
 */

export interface ThrottleConfig {
  maxRequestsPerMinute?: number
  jitterMs?: number
  concurrencyLimit?: number
}

export class OpsecThrottleEngine {
  private config: Required<ThrottleConfig>

  constructor(config: ThrottleConfig = {}) {
    this.config = {
      maxRequestsPerMinute: config.maxRequestsPerMinute ?? 60,
      jitterMs: config.jitterMs ?? 200,
      concurrencyLimit: config.concurrencyLimit ?? 3,
    }
  }

  /**
   * Applies deliberate delay and random jitter between tool invocations.
   */
  public async paceExecution(): Promise<void> {
    const baseDelay = (60 / this.config.maxRequestsPerMinute) * 1000
    const jitter = Math.random() * this.config.jitterMs
    const totalDelay = Math.floor(baseDelay + jitter)

    await new Promise((resolve) => setTimeout(resolve, totalDelay))
  }

  /**
   * Get current throttling parameters.
   */
  public getConfig(): Required<ThrottleConfig> {
    return { ...this.config }
  }
}

export default new OpsecThrottleEngine()
