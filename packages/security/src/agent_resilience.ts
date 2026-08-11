/**
 * @module security/agent_resilience
 * Deterministic Execution, Schema Validation & Context Recovery Engine
 * Protects autonomous subagents against LLM hallucinations, parameter formatting errors, and token context limits.
 */

export interface ToolCallAttempt {
  toolName: string
  rawParameters: Record<string, unknown>
  validatedParameters?: Record<string, unknown>
  status: "VALIDATED" | "REPAIRED" | "FAILED"
  repairNotes?: string
}

export interface ContextCheckpoint {
  sessionId: string
  timestamp: string
  stepCount: number
  summary: string
  activeTaskIds: string[]
}

export class AgentResilienceEngine {
  private checkpoints: Map<string, ContextCheckpoint[]> = new Map()

  /**
   * Validates and repairs common tool call parameter hallucinations.
   */
  public validateAndRepairToolCall(toolName: string, params: Record<string, unknown>): ToolCallAttempt {
    const repaired: Record<string, unknown> = { ...params }
    let isRepaired = false
    const notes: string[] = []

    // Ensure string fields expected by modules are non-null
    for (const [key, value] of Object.entries(repaired)) {
      if (value === null || value === undefined) {
        repaired[key] = ""
        isRepaired = true
        notes.push(`Converted null/undefined parameter '${key}' to empty string.`)
      }
    }

    // Fix stringified boolean hallucinations (e.g. "true" -> true)
    if (typeof repaired["live"] === "string") {
      repaired["live"] = repaired["live"] === "true"
      isRepaired = true
      notes.push("Converted string 'live' parameter to boolean.")
    }

    return {
      toolName,
      rawParameters: params,
      validatedParameters: repaired,
      status: isRepaired ? "REPAIRED" : "VALIDATED",
      repairNotes: notes.join(" "),
    }
  }

  /**
   * Save session checkpoint to prevent state loss during long executions.
   */
  public saveCheckpoint(sessionId: string, stepCount: number, summary: string, activeTaskIds: string[]): ContextCheckpoint {
    const checkpoint: ContextCheckpoint = {
      sessionId,
      timestamp: new Date().toISOString(),
      stepCount,
      summary,
      activeTaskIds,
    }

    const history = this.checkpoints.get(sessionId) ?? []
    history.push(checkpoint)
    this.checkpoints.set(sessionId, history)

    return checkpoint
  }

  /**
   * Retrieve the latest checkpoint for session recovery.
   */
  public getLatestCheckpoint(sessionId: string): ContextCheckpoint | undefined {
    const history = this.checkpoints.get(sessionId)
    return history?.[history.length - 1]
  }
}

export const resilienceEngine = new AgentResilienceEngine()
export default resilienceEngine
