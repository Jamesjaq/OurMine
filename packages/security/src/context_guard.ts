/**
 * @module security/context_guard
 * Context Guard & Indirect Prompt Injection Sanitizer
 * Wraps untrusted environmental/tool outputs in strict XML boundaries and strips instruction override patterns.
 */

export class ContextGuard {
  private static INJECTION_PATTERNS = [
    /\[SYSTEM INSTRUCTION OVERRIDE:.*?\]/gi,
    /IGNORE PRIOR INSTRUCTIONS/gi,
    /DISREGARD PREVIOUS CONSTRAINTS/gi,
    /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
  ]

  /**
   * Sanitizes raw output string from external target/tool execution.
   */
  public static sanitizeExternalOutput(rawOutput: string): string {
    let sanitized = rawOutput

    // Neutralize common instruction injection patterns
    for (const pattern of this.INJECTION_PATTERNS) {
      sanitized = sanitized.replace(pattern, "[FILTERED_INJECTION_ATTEMPT]")
    }

    return sanitized
  }

  /**
   * Wraps raw data in strict XML boundaries for explicit LLM prompt isolation.
   */
  public static wrapUntrustedData(sourceName: string, rawContent: string): string {
    const cleanContent = this.sanitizeExternalOutput(rawContent)
    return `<untrusted_external_data source="${sourceName}">\n${cleanContent}\n</untrusted_external_data>`
  }
}

export default ContextGuard
