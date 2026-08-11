/**
 * @module security/finding_lifecycle
 * Explicit state machine for vulnerability findings.
 *
 * Legal transitions:
 *   DISCOVERED → OBSERVED → SUSPECTED → VALIDATION_PENDING → VALIDATING
 *                                             → CONFIRMED
 *                                             → FALSE_POSITIVE
 *                                             → UNVERIFIED
 *
 * The LLM has NO path to call transition() into CONFIRMED.
 * Only ValidationEngine.execute() may do that, and only with attached evidence.
 */

export const FINDING_STATES = [
  "DISCOVERED",
  "OBSERVED",
  "SUSPECTED",
  "VALIDATION_PENDING",
  "VALIDATING",
  "CONFIRMED",
  "FALSE_POSITIVE",
  "UNVERIFIED",
] as const

export type FindingState = typeof FINDING_STATES[number]

// Legal forward transitions only. No backward transitions allowed except
// VALIDATING → UNVERIFIED (when validator fails or times out).
const LEGAL_TRANSITIONS: Record<FindingState, FindingState[]> = {
  DISCOVERED:          ["OBSERVED"],
  OBSERVED:            ["SUSPECTED"],
  SUSPECTED:           ["VALIDATION_PENDING", "UNVERIFIED"],
  VALIDATION_PENDING:  ["VALIDATING", "UNVERIFIED"],
  VALIDATING:          ["CONFIRMED", "FALSE_POSITIVE", "UNVERIFIED"],
  CONFIRMED:           [],
  FALSE_POSITIVE:      [],
  UNVERIFIED:          ["VALIDATION_PENDING"],  // allow retry after expiry
}

export class FindingStateMachine {
  private state: FindingState
  private history: Array<{ from: FindingState; to: FindingState; reason: string; ts: string }> = []

  constructor(initial: FindingState = "DISCOVERED") {
    this.state = initial
  }

  get current(): FindingState {
    return this.state
  }

  get transitions(): readonly FindingState[] {
    return LEGAL_TRANSITIONS[this.state]
  }

  /**
   * Attempt a transition. Returns true on success, throws on illegal transition.
   * caller MUST supply a reason — this feeds the audit trail.
   */
  transition(to: FindingState, reason: string): void {
    if (!LEGAL_TRANSITIONS[this.state].includes(to)) {
      throw new Error(
        `[FindingStateMachine] Illegal transition ${this.state} → ${to}. ` +
        `Allowed: [${LEGAL_TRANSITIONS[this.state].join(", ")}]`
      )
    }
    this.history.push({ from: this.state, to, reason, ts: new Date().toISOString() })
    this.state = to
  }

  canTransitionTo(to: FindingState): boolean {
    return LEGAL_TRANSITIONS[this.state].includes(to)
  }

  getHistory() {
    return [...this.history]
  }

  /** Serialize for graph persistence */
  toJSON() {
    return { state: this.state, history: this.history }
  }

  static fromJSON(data: { state: FindingState; history: any[] }): FindingStateMachine {
    const sm = new FindingStateMachine(data.state)
    sm.history = data.history
    return sm
  }
}
