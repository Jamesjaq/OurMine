/**
 * @module identity_theft
 * Identity Theft & PII Harvesting Simulator — PII Sanitizer & Masker, Dark Web Leak Correlator,
 * SSN/SIN Format Verifier, and Synthetic Identity Detection Engine.
 */

export function maskPII(text: string): string {
  // Mask emails and SSNs
  return text
    .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, "[EMAIL_MASKED]")
    .replace(/\b\d{3}-\d{2}-\d{4}\b/g, "XXX-XX-XXXX");
}

export default { maskPII };
