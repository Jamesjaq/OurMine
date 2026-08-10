/**
 * @module carding
 * Payment Card Security & Validation — Luhn Algorithm Checksum Verifier, BIN (Bank Identification Number) Lookups,
 * Track 1 / Track 2 Magstripe Format Decoders, and OPSEC Controls for Card Data.
 */

export function validateLuhn(cardNumber: string): boolean {
  const clean = cardNumber.replace(/\D/g, "");
  let sum = 0;
  let shouldDouble = false;

  for (let i = clean.length - 1; i >= 0; i--) {
    let digit = parseInt(clean.charAt(i), 10);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }

  return sum % 10 === 0;
}

export default { validateLuhn };
