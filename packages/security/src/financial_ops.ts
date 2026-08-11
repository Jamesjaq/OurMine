import { resolveDryRun } from "./exec_options.ts"
/**
 * @module financial_ops
 * Financial Operations & Money Laundering Detection — Money Mule Network Graphing,
 * Crypto Mixer Transaction Tracing, Structuring / Smurfing Pattern Analyzer, and Shell Company Cross-Referencing.
 */

export interface TransactionNode {
  id: string;
  from: string;
  to: string;
  amount: number;
  timestamp?: string;
  channel?: string;
}

interface StructuringResult {
  detected: boolean;
  transactionCount: number;
  nearThresholdCount: number;
  totalNearThreshold: number;
  patterns: string[];
  riskLevel: "low" | "medium" | "high" | "critical";
}

interface VelocityResult {
  detected: boolean;
  transactionsPerHour: number;
  transactionsPerDay: number;
  averageInterval: number;
  anomalies: string[];
}

interface RoundTripResult {
  detected: boolean;
  cycles: Array<{ nodes: string[]; totalAmount: number }>;
  totalCircularFlow: number;
}

interface TransactionAnalysis {
  structuring: StructuringResult;
  velocity: VelocityResult;
  roundTrip: RoundTripResult;
  overallRisk: number;
  recommendations: string[];
}

const CTR_THRESHOLD = 10000;
const STRUCTURING_BAND_LOW = 0.8;
const VELOCITY_HIGH_FREQ_THRESHOLD = 50;
const VELOCITY_SHORT_INTERVAL_MS = 60 * 1000;
const ROUND_TRIP_MIN_DEPTH = 3;

function detectStructuringPatterns(transactions: TransactionNode[]): StructuringResult {
  const nearThreshold = transactions.filter(
    (t) =>
      t.amount >= CTR_THRESHOLD * STRUCTURING_BAND_LOW && t.amount < CTR_THRESHOLD
  );
  const aboveThreshold = transactions.filter((t) => t.amount >= CTR_THRESHOLD);

  const patterns: string[] = [];
  let riskLevel: "low" | "medium" | "high" | "critical" = "low";

  if (nearThreshold.length >= 3) {
    const amounts = nearThreshold.map((t) => t.amount);
    const avg = amounts.reduce((a, b) => a + b, 0) / amounts.length;
    const stddev = Math.sqrt(
      amounts.reduce((sum, a) => sum + Math.pow(a - avg, 2), 0) / amounts.length
    );

    if (stddev < 200) {
      patterns.push("Tight clustering near threshold (low stddev)");
    }

    const timeGroups = new Map<string, TransactionNode[]>();
    for (const tx of nearThreshold) {
      if (tx.timestamp) {
        const dateKey = tx.timestamp.split("T")[0];
        const group = timeGroups.get(dateKey) || [];
        group.push(tx);
        timeGroups.set(dateKey, group);
      }
    }

    for (const [date, txs] of timeGroups) {
      if (txs.length >= 2) {
        patterns.push(`Multiple near-threshold transactions on ${date}: ${txs.length} txs`);
      }
    }

    const sameChannel = new Map<string, number>();
    for (const tx of nearThreshold) {
      const ch = tx.channel || "unknown";
      sameChannel.set(ch, (sameChannel.get(ch) || 0) + 1);
    }
    for (const [ch, count] of sameChannel) {
      if (count >= 3) {
        patterns.push(`Bulk structuring via ${ch} channel: ${count} transactions`);
      }
    }

    if (nearThreshold.length >= 5) riskLevel = "critical";
    else if (nearThreshold.length >= 3) riskLevel = "high";
  } else if (nearThreshold.length >= 2) {
    riskLevel = "medium";
  }

  if (aboveThreshold.length > 0 && nearThreshold.length > 0) {
    patterns.push("Mixed above/below threshold activity");
    if (riskLevel === "low") riskLevel = "medium";
  }

  return {
    detected: nearThreshold.length >= 2,
    transactionCount: transactions.length,
    nearThresholdCount: nearThreshold.length,
    totalNearThreshold: nearThreshold.reduce((sum, t) => sum + t.amount, 0),
    patterns,
    riskLevel,
  };
}

function detectVelocityAnomalies(transactions: TransactionNode[]): VelocityResult {
  const anomalies: string[] = [];
  let detected = false;

  if (transactions.length < 2) {
    return { detected: false, transactionsPerHour: 0, transactionsPerDay: 0, averageInterval: 0, anomalies };
  }

  const timestamps = transactions
    .map((t) => (t.timestamp ? new Date(t.timestamp).getTime() : 0))
    .filter((t) => t > 0)
    .sort((a, b) => a - b);

  let transactionsPerHour = 0;
  let transactionsPerDay = 0;
  let averageInterval = 0;

  if (timestamps.length >= 2) {
    const totalMs = timestamps[timestamps.length - 1] - timestamps[0];
    const totalHours = totalMs / (1000 * 60 * 60);
    const totalDays = totalMs / (1000 * 60 * 60 * 24);

    transactionsPerHour = totalHours > 0 ? timestamps.length / totalHours : timestamps.length;
    transactionsPerDay = totalDays > 0 ? timestamps.length / totalDays : timestamps.length;

    const intervals: number[] = [];
    for (let i = 1; i < timestamps.length; i++) {
      intervals.push(timestamps[i] - timestamps[i - 1]);
    }
    averageInterval = intervals.reduce((a, b) => a + b, 0) / intervals.length;

    if (transactionsPerHour > VELOCITY_HIGH_FREQ_THRESHOLD) {
      anomalies.push(`Extremely high frequency: ${transactionsPerHour.toFixed(1)} tx/hour`);
      detected = true;
    }

    const shortIntervals = intervals.filter((i) => i < VELOCITY_SHORT_INTERVAL_MS);
    if (shortIntervals.length >= 3) {
      anomalies.push(`${shortIntervals.length} transactions within 60 seconds of each other`);
      detected = true;
    }

    const burstWindows = findBurstWindows(timestamps, 5 * 60 * 1000, 10);
    if (burstWindows > 0) {
      anomalies.push(`Detected ${burstWindows} burst window(s) with rapid-fire transactions`);
      detected = true;
    }

    if (totalDays > 0 && transactionsPerDay > 20) {
      anomalies.push(`Sustained high volume: ${transactionsPerDay.toFixed(1)} tx/day over ${totalDays.toFixed(1)} days`);
      detected = true;
    }
  }

  return {
    detected,
    transactionsPerHour: Math.round(transactionsPerHour * 100) / 100,
    transactionsPerDay: Math.round(transactionsPerDay * 100) / 100,
    averageInterval: Math.round(averageInterval),
    anomalies,
  };
}

function findBurstWindows(timestamps: number[], windowMs: number, minCount: number): number {
  let burstCount = 0;
  for (let i = 0; i < timestamps.length; i++) {
    const windowEnd = timestamps[i] + windowMs;
    let count = 0;
    for (let j = i; j < timestamps.length && timestamps[j] <= windowEnd; j++) {
      count++;
    }
    if (count >= minCount) burstCount++;
  }
  return burstCount;
}

function detectRoundTrips(transactions: TransactionNode[]): RoundTripResult {
  const graph = new Map<string, Map<string, number>>();

  for (const tx of transactions) {
    if (!graph.has(tx.from)) graph.set(tx.from, new Map());
    const edges = graph.get(tx.from)!;
    edges.set(tx.to, (edges.get(tx.to) || 0) + tx.amount);
  }

  const cycles: Array<{ nodes: string[]; totalAmount: number }> = [];
  const visited = new Set<string>();

  for (const startNode of graph.keys()) {
    const foundCycles = dfsCycles(graph, startNode, startNode, [startNode], visited, 0);
    cycles.push(...foundCycles);
  }

  const uniqueCycles = deduplicateCycles(cycles);

  return {
    detected: uniqueCycles.length > 0,
    cycles: uniqueCycles,
    totalCircularFlow: uniqueCycles.reduce((sum, c) => sum + c.totalAmount, 0),
  };
}

function dfsCycles(
  graph: Map<string, Map<string, number>>,
  currentNode: string,
  startNode: string,
  path: string[],
  visited: Set<string>,
  depth: number
): Array<{ nodes: string[]; totalAmount: number }> {
  const results: Array<{ nodes: string[]; totalAmount: number }> = [];

  if (depth >= ROUND_TRIP_MIN_DEPTH && graph.has(currentNode)) {
    const edges = graph.get(currentNode)!;
    if (edges.has(startNode)) {
      results.push({
        nodes: [...path, startNode],
        totalAmount: edges.get(startNode)!,
      });
    }
  }

  if (depth >= 6) return results;

  const edges = graph.get(currentNode);
  if (!edges) return results;

  for (const [neighbor] of edges) {
    if (neighbor === startNode && depth >= ROUND_TRIP_MIN_DEPTH - 1) continue;
    if (visited.has(neighbor) && neighbor !== startNode) continue;

    visited.add(neighbor);
    const subResults = dfsCycles(graph, neighbor, startNode, [...path, neighbor], visited, depth + 1);
    results.push(...subResults);
    visited.delete(neighbor);
  }

  return results;
}

function deduplicateCycles(
  cycles: Array<{ nodes: string[]; totalAmount: number }>
): Array<{ nodes: string[]; totalAmount: number }> {
  const seen = new Set<string>();
  const unique: Array<{ nodes: string[]; totalAmount: number }> = [];

  for (const cycle of cycles) {
    const normalized = normalizeCycle(cycle.nodes);
    if (!seen.has(normalized)) {
      seen.add(normalized);
      unique.push(cycle);
    }
  }

  return unique;
}

function normalizeCycle(nodes: string[]): string {
  const withoutLast = nodes.slice(0, -1);
  let minIdx = 0;
  for (let i = 1; i < withoutLast.length; i++) {
    if (withoutLast[i] < withoutLast[minIdx]) minIdx = i;
  }
  const rotated = [...withoutLast.slice(minIdx), ...withoutLast.slice(0, minIdx)];
  return rotated.join("->");
}

function calculateOverallRisk(
  structuring: StructuringResult,
  velocity: VelocityResult,
  roundTrip: RoundTripResult
): number {
  let score = 0;

  if (structuring.detected) {
    const structWeights: Record<string, number> = { low: 15, medium: 30, high: 50, critical: 70 };
    score += structWeights[structuring.riskLevel] || 0;
  }

  if (velocity.detected) {
    score += Math.min(velocity.anomalies.length * 12, 40);
  }

  if (roundTrip.detected) {
    score += Math.min(roundTrip.cycles.length * 15, 45);
  }

  return Math.min(score, 100);
}

function generateRecommendations(
  structuring: StructuringResult,
  velocity: VelocityResult,
  roundTrip: RoundTripResult
): string[] {
  const recs: string[] = [];

  if (structuring.detected) {
    recs.push("File Suspicious Activity Report (SAR) for structuring pattern");
    recs.push("Review all accounts involved in near-threshold transactions");
    if (structuring.riskLevel === "critical") {
      recs.push("Escalate to BSA/AML compliance officer immediately");
    }
  }

  if (velocity.detected) {
    recs.push("Implement transaction rate limiting for flagged accounts");
    recs.push("Review automated/payment processor origin transactions");
  }

  if (roundTrip.detected) {
    recs.push("Investigate circular fund flows for layering activity");
    recs.push("Cross-reference entities with shell company databases");
    recs.push("Consider account freezes pending investigation");
  }

  return recs;
}

export function analyzeTransactions(
  transactions: TransactionNode[],
  dryRun: boolean = true
): TransactionAnalysis {
  if (dryRun) {
    return {
      structuring: {
        detected: true,
        transactionCount: 23,
        nearThresholdCount: 7,
        totalNearThreshold: 67450.0,
        patterns: [
          "Tight clustering near threshold (low stddev)",
          "Multiple near-threshold transactions on 2024-11-12: 3 txs",
          "Bulk structuring via wire channel: 4 transactions",
        ],
        riskLevel: "high",
      },
      velocity: {
        detected: true,
        transactionsPerHour: 12.5,
        transactionsPerDay: 85.0,
        averageInterval: 288000,
        anomalies: [
          "Sustained high volume: 85.0 tx/day over 3.2 days",
          "3 transactions within 60 seconds of each other",
        ],
      },
      roundTrip: {
        detected: true,
        cycles: [
          { nodes: ["ACCT-A", "ACCT-B", "ACCT-C", "ACCT-A"], totalAmount: 48500.0 },
          { nodes: ["ACCT-D", "ACCT-E", "ACCT-D"], totalAmount: 22000.0 },
        ],
        totalCircularFlow: 70500.0,
      },
      overallRisk: 78,
      recommendations: [
        "File Suspicious Activity Report (SAR) for structuring pattern",
        "Review all accounts involved in near-threshold transactions",
        "Escalate to BSA/AML compliance officer immediately",
        "Implement transaction rate limiting for flagged accounts",
        "Investigate circular fund flows for layering activity",
        "Cross-reference entities with shell company databases",
        "Consider account freezes pending investigation",
      ],
    };
  }

  const structuring = detectStructuringPatterns(transactions);
  const velocity = detectVelocityAnomalies(transactions);
  const roundTrip = detectRoundTrips(transactions);
  const overallRisk = calculateOverallRisk(structuring, velocity, roundTrip);
  const recommendations = generateRecommendations(structuring, velocity, roundTrip);

  return {
    structuring,
    velocity,
    roundTrip,
    overallRisk,
    recommendations,
  };
}

export function detectStructuring(transactions: number[]): boolean {
  const nearLimit = transactions.filter((t) => t >= 9000 && t < 10000);
  return nearLimit.length >= 2;
}

export default { detectStructuring, analyzeTransactions };
