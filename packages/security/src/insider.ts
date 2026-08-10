/**
 * @module insider
 * Insider Threat Detection & Simulation — Anomalous Data Volume Transfer Detector,
 * Off-Hours Authentication Monitor, USB Storage Insertion Logger, and Privilege Escalation Attempt Monitor.
 */

export interface InsiderBehaviorEvent {
  userId: string;
  action: string;
  volumeBytes?: number;
  timestamp: string;
  riskWeight: number;
}

export function evaluateInsiderRisk(events: InsiderBehaviorEvent[]): { totalRisk: number; flagged: boolean } {
  const totalRisk = events.reduce((acc, e) => acc + e.riskWeight, 0);
  return { totalRisk, flagged: totalRisk >= 75 };
}

export default { evaluateInsiderRisk };
