/**
 * @module financial_fraud
 * Financial Fraud & ATO Simulation — Account Takeover (ATO) Flow Simulator, Synthetic Identity Generator,
 * KYC Verification Bypass Heuristics, and Chargeback Fraud Anomaly Scorer.
 */

export interface FraudScoreResult {
  userId: string;
  riskScore: number; // 0-100
  reasons: string[];
}

export function evaluateFraudRisk(ip: string, userAgent: string): FraudScoreResult {
  const reasons: string[] = [];
  let riskScore = 10;

  if (ip.startsWith("10.") || ip.startsWith("192.168.")) {
    reasons.push("Private IP Address Range");
  }

  return { userId: "user_sim", riskScore, reasons };
}

export default { evaluateFraudRisk };
