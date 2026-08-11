/**
 * @module insider
 * Insider Threat Detection & Simulation — Anomalous Data Volume Transfer Detector,
 * Off-Hours Authentication Monitor, Behavioral Baseline Modeling, and Risk Scoring.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as path from "node:path";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface InsiderBehaviorEvent {
  userId: string;
  action: string;
  volumeBytes?: number;
  timestamp: string;
  riskWeight: number;
  source?: string;
  sourceIp?: string;
  targetResource?: string;
}

export interface InsiderOptions {
  dryRun?: boolean;
  baselineWindowDays?: number;
  volumeThresholdBytes?: number;
  riskThreshold?: number;
  timeOfDayStart?: number; // hour 0-23
  timeOfDayEnd?: number;   // hour 0-23
}

export interface AuthLogEntry {
  timestamp: string;
  userId: string;
  sourceIp: string;
  result: "success" | "failure";
  service: string;
  method: string;
}

export interface FileAccessLogEntry {
  timestamp: string;
  userId: string;
  filePath: string;
  action: "read" | "write" | "delete" | "copy" | "rename";
  bytesTransferred?: number;
  processName?: string;
}

export interface RiskEvaluation {
  totalRisk: number;
  /** Alias for totalRisk (legacy tests/CLI) */
  riskScore?: number;
  flagged: boolean;
  breakdown: {
    volumeRisk: number;
    timeRisk: number;
    frequencyRisk: number;
    behavioralRisk: number;
  };
  anomalies: string[];
  dryRun: boolean;
}

export interface BehavioralBaseline {
  userId: string;
  avgDailyActions: number;
  avgActionVolume: number;
  peakHours: number[];
  typicalActions: Map<string, number>;
  sampleCount: number;
  dryRun: boolean;
}

// ─── Risk Weights ─────────────────────────────────────────────────────────────

const ACTION_RISK_WEIGHTS: Record<string, number> = {
  "download": 40,
  "upload": 35,
  "delete": 50,
  "copy": 25,
  "rename": 10,
  "read": 5,
  "write": 15,
  "login_failure": 20,
  "login_success": 2,
  "privilege_escalation": 60,
  "data_exfil": 80,
  "usb_insert": 30,
  "email_forward": 45,
  "shared_folder_access": 20,
  "admin_action": 55,
};

// ─── Log Parsing ──────────────────────────────────────────────────────────────

/**
 * Parse a generic auth log line (supports syslog, Windows Event Log CSV, and JSON).
 * DRY-RUN: returns simulated log entries.
 */
export function parseAuthLog(
  logContent: string,
  format: "syslog" | "csv" | "json" = "syslog",
): AuthLogEntry[] {
  const entries: AuthLogEntry[] = [];

  if (!logContent.trim()) {
    return [];
  }

  for (const line of logContent.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    try {
      if (format === "json") {
        const obj = JSON.parse(trimmed);
        entries.push({
          timestamp: obj.timestamp ?? obj.time ?? obj["@timestamp"] ?? "",
          userId: obj.user ?? obj.username ?? obj.userId ?? "",
          sourceIp: obj.src_ip ?? obj.source_ip ?? obj.srcIp ?? "",
          result: /fail|denied|error/i.test(String(obj.result ?? obj.status ?? "")) ? "failure" : "success",
          service: obj.service ?? obj.application ?? "",
          method: obj.method ?? obj.auth_method ?? "",
        });
      } else if (format === "csv") {
        const parts = trimmed.split(",").map((s) => s.trim());
        if (parts.length >= 5) {
          entries.push({
            timestamp: parts[0],
            userId: parts[1],
            sourceIp: parts[2],
            result: /fail|denied|error/i.test(parts[3]) ? "failure" : "success",
            service: parts[4],
            method: parts[5] ?? "",
          });
        }
      } else {
        // syslog-style: "timestamp hostname service[user]: message"
        const match = trimmed.match(
          /^(\w{3}\s+\d+\s+[\d:]+)\s+\S+\s+(\S+)\[?(\w*)\]?:?\s+(.*)/i,
        );
        if (match) {
          const message = match[4] ?? "";
          entries.push({
            timestamp: match[1],
            userId: match[3] || "unknown",
            sourceIp: "",
            result: /fail|denied|invalid|error/i.test(message) ? "failure" : "success",
            service: match[2],
            method: "",
          });
        }
      }
    } catch {
      // skip unparseable lines
    }
  }

  return entries;
}

/**
 * Parse file access audit logs (Linux auditd, Windows Sysmon, or JSON format).
 * DRY-RUN: returns simulated file access entries.
 */
export function parseFileAccessLog(
  logContent: string,
  format: "auditd" | "sysmon" | "json" = "json",
): FileAccessLogEntry[] {
  const entries: FileAccessLogEntry[] = [];

  if (!logContent.trim()) {
    return [];
  }

  for (const line of logContent.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;

    try {
      if (format === "json") {
        const obj = JSON.parse(trimmed);
        entries.push({
          timestamp: obj.timestamp ?? obj.time ?? "",
          userId: obj.user ?? obj.username ?? "",
          filePath: obj.file ?? obj.path ?? obj.filePath ?? "",
          action: (obj.action ?? obj.operation ?? "read") as FileAccessLogEntry["action"],
          bytesTransferred: obj.bytes ?? obj.size ?? obj.bytesTransferred ?? 0,
          processName: obj.process ?? obj.processName ?? "",
        });
      } else if (format === "auditd") {
        // auditd SYSCALL format
        const actionMatch = trimmed.match(/SYSCALL.*syscall=(\w+)/);
        const fileMatch = trimmed.match(/PATH.*name="([^"]+)"/);
        const uidMatch = trimmed.match(/uid=(\w+)/);
        if (fileMatch) {
          const syscallMap: Record<string, FileAccessLogEntry["action"]> = {
            read: "read", open: "read", write: "write", creat: "write",
            unlink: "delete", rename: "rename", copy_file_range: "copy",
          };
          const syscall = actionMatch?.[1] ?? "read";
          entries.push({
            timestamp: new Date().toISOString(),
            userId: uidMatch?.[1] ?? "",
            filePath: fileMatch[1],
            action: syscallMap[syscall] ?? "read",
          });
        }
      } else if (format === "sysmon") {
        const obj = JSON.parse(trimmed);
        entries.push({
          timestamp: obj.UtcTime ?? "",
          userId: obj.User ?? "",
          filePath: obj.TargetFilename ?? obj.Image ?? "",
          action: obj.EventID === 11 ? "write" : "read",
          processName: obj.Image ?? "",
        });
      }
    } catch {
      // skip unparseable lines
    }
  }

  return entries;
}

// ─── Behavioral Baseline Modeling ─────────────────────────────────────────────

/**
 * Build a behavioral baseline from historical events for a specific user.
 * DRY-RUN: returns a synthetic baseline from the provided events.
 */
export function buildBaseline(
  events: InsiderBehaviorEvent[],
  userId: string,
  opts: InsiderOptions = {},
): BehavioralBaseline {
  const { dryRun = true } = opts;
  const userEvents = events.filter((e) => e.userId === userId);

  if (userEvents.length === 0) {
    return {
      userId,
      avgDailyActions: 0,
      avgActionVolume: 0,
      peakHours: [],
      typicalActions: new Map(),
      sampleCount: 0,
      dryRun,
    };
  }

  // Compute time span
  const timestamps = userEvents.map((e) => new Date(e.timestamp).getTime());
  const minTime = Math.min(...timestamps);
  const maxTime = Math.max(...timestamps);
  const daySpan = Math.max(1, (maxTime - minTime) / (1000 * 60 * 60 * 24));

  // Average daily action count
  const avgDailyActions = userEvents.length / daySpan;

  // Average action volume
  const volumes = userEvents.filter((e) => e.volumeBytes !== undefined).map((e) => e.volumeBytes!);
  const avgActionVolume = volumes.length > 0 ? volumes.reduce((a, b) => a + b, 0) / volumes.length : 0;

  // Peak hours histogram
  const hourCounts = new Array(24).fill(0) as number[];
  for (const e of userEvents) {
    const hour = new Date(e.timestamp).getHours();
    hourCounts[hour]++;
  }
  const sortedHours = hourCounts
    .map((count, hour) => ({ hour, count }))
    .sort((a, b) => b.count - a.count);
  const peakHours = sortedHours.slice(0, 3).map((h) => h.hour);

  // Typical action distribution
  const actionCounts = new Map<string, number>();
  for (const e of userEvents) {
    actionCounts.set(e.action, (actionCounts.get(e.action) ?? 0) + 1);
  }

  return {
    userId,
    avgDailyActions,
    avgActionVolume,
    peakHours,
    typicalActions: actionCounts,
    sampleCount: userEvents.length,
    dryRun,
  };
}

// ─── Volume Threshold Detection ───────────────────────────────────────────────

/**
 * Detect anomalous data volume transfers exceeding a threshold.
 * DRY-RUN: returns simulated anomalies without real-time monitoring.
 */
export function detectVolumeAnomalies(
  events: InsiderBehaviorEvent[],
  opts: InsiderOptions = {},
): InsiderBehaviorEvent[] {
  const { dryRun = true, volumeThresholdBytes = 100 * 1024 * 1024 } = opts; // 100 MB default

  const anomalies = events.filter((e) => {
    if (e.volumeBytes === undefined) return false;
    return e.volumeBytes > volumeThresholdBytes;
  });

  return anomalies;
}

// ─── Time-of-Day Analysis ─────────────────────────────────────────────────────

/**
 * Analyze events for off-hours activity (outside normal business hours).
 * DRY-RUN: returns simulated off-hours findings.
 */
export function analyzeTimeOfDay(
  events: InsiderBehaviorEvent[],
  opts: InsiderOptions = {},
): InsiderBehaviorEvent[] {
  const {
    dryRun = true,
    timeOfDayStart = 9,  // 9 AM
    timeOfDayEnd = 17,   // 5 PM
  } = opts;

  const offHours = events.filter((e) => {
    const hour = new Date(e.timestamp).getHours();
    return hour < timeOfDayStart || hour >= timeOfDayEnd;
  });

  return offHours;
}

// ─── Frequency Analysis ───────────────────────────────────────────────────────

/**
 * Detect unusual action frequency compared to the baseline.
 * DRY-RUN: returns synthetic frequency anomalies.
 */
export function detectFrequencyAnomalies(
  events: InsiderBehaviorEvent[],
  baseline: BehavioralBaseline,
  opts: InsiderOptions = {},
): { action: string; count: number; baselineAvg: number; deviation: number }[] {
  const { dryRun = true } = opts;

  // Group events by action type
  const actionCounts = new Map<string, number>();
  for (const e of events) {
    actionCounts.set(e.action, (actionCounts.get(e.action) ?? 0) + 1);
  }

  const anomalies: { action: string; count: number; baselineAvg: number; deviation: number }[] = [];

  for (const [action, count] of actionCounts) {
    const baselineAvg = baseline.typicalActions.get(action) ?? 0;
    const normalizedBaseline = baselineAvg / Math.max(baseline.sampleCount, 1) * events.length;
    const deviation = normalizedBaseline > 0 ? (count - normalizedBaseline) / normalizedBaseline : count;

    if (Math.abs(deviation) > 0.5) {
      anomalies.push({ action, count, baselineAvg: normalizedBaseline, deviation });
    }
  }

  return anomalies;
}

// ─── Full Risk Evaluation ─────────────────────────────────────────────────────

/**
 * Evaluate insider threat risk across all dimensions.
 * DRY-RUN: returns simulated risk assessment without real-time monitoring.
 */
export function evaluateInsiderRisk(
  events: InsiderBehaviorEvent[],
  opts: InsiderOptions = {},
): RiskEvaluation {
  const { dryRun = true, riskThreshold = 75, volumeThresholdBytes, timeOfDayStart, timeOfDayEnd } = opts;

  // Volume risk
  const volumeAnomalies = detectVolumeAnomalies(events, { dryRun, volumeThresholdBytes });
  const volumeRisk = Math.min(100, volumeAnomalies.length * 25);

  // Time-of-day risk
  const offHoursEvents = analyzeTimeOfDay(events, { dryRun, timeOfDayStart, timeOfDayEnd });
  const timeRisk = Math.min(100, offHoursEvents.length * 20);

  // Frequency risk (using a synthetic baseline if none provided)
  const baseline = buildBaseline(events, events[0]?.userId ?? "", { dryRun });
  const freqAnomalies = detectFrequencyAnomalies(events, baseline, { dryRun });
  const frequencyRisk = Math.min(100, freqAnomalies.length * 20);

  // Behavioral risk from direct risk weights
  const behavioralRisk = Math.min(
    100,
    events.reduce((sum, e) => sum + e.riskWeight, 0) / Math.max(events.length, 1),
  );

  // Weighted total
  const totalRisk = Math.min(
    100,
    Math.round(
      volumeRisk * 0.25 +
      timeRisk * 0.20 +
      frequencyRisk * 0.20 +
      behavioralRisk * 0.35,
    ),
  );

  // Anomaly descriptions
  const anomalies: string[] = [];
  if (volumeRisk > 30) anomalies.push(`${volumeAnomalies.length} volume threshold breach(es) detected`);
  if (timeRisk > 30) anomalies.push(`${offHoursEvents.length} off-hours event(s) detected`);
  if (frequencyRisk > 30) anomalies.push(`${freqAnomalies.length} frequency anomaly/anomalies detected`);
  if (behavioralRisk > 50) anomalies.push("Elevated risk-weight activity from behavioral analysis");

  return {
    totalRisk,
    riskScore: totalRisk,
    flagged: totalRisk >= riskThreshold,
    breakdown: { volumeRisk, timeRisk, frequencyRisk, behavioralRisk },
    anomalies,
    dryRun,
  };
}

// ─── Real-Time Monitoring Simulator ───────────────────────────────────────────

export interface MonitoringSession {
  sessionId: string;
  userId: string;
  events: InsiderBehaviorEvent[];
  baseline: BehavioralBaseline | null;
  startTime: string;
  dryRun: boolean;
}

/**
 * Start a monitoring session for a specific user.
 * DRY-RUN: simulates the monitoring session without file system access.
 */
export function startMonitoring(
  userId: string,
  logDir?: string,
  opts: InsiderOptions = {},
): MonitoringSession {
  const { dryRun = true } = opts;

  let events: InsiderBehaviorEvent[] = [];

  if (!dryRun && logDir && fs.existsSync(logDir)) {
    // Read real log files from directory
    const files = fs.readdirSync(logDir).filter((f) => f.endsWith(".log") || f.endsWith(".json"));
    for (const file of files) {
      const content = fs.readFileSync(path.join(logDir, file), "utf8");
      const parsed = parseFileAccessLog(content, "json");
      events.push(
        ...parsed.map((entry) => ({
          userId: entry.userId,
          action: entry.action,
          volumeBytes: entry.bytesTransferred,
          timestamp: entry.timestamp,
          riskWeight: ACTION_RISK_WEIGHTS[entry.action] ?? 10,
          source: "file_access_log",
          sourceIp: "",
          targetResource: entry.filePath,
        })),
      );
    }
  }

  if (dryRun) {
    events = [];
  }

  return {
    sessionId: crypto.randomUUID(),
    userId,
    events,
    baseline: events.length > 0 ? buildBaseline(events, userId, { dryRun }) : null,
    startTime: new Date().toISOString(),
    dryRun,
  };
}

/**
 * Evaluate a monitoring session and return a risk assessment.
 */
export function evaluateSession(
  session: MonitoringSession,
  opts: InsiderOptions = {},
): RiskEvaluation {
  return evaluateInsiderRisk(session.events, { ...opts, dryRun: session.dryRun });
}

export default {
  parseAuthLog,
  parseFileAccessLog,
  buildBaseline,
  detectVolumeAnomalies,
  analyzeTimeOfDay,
  detectFrequencyAnomalies,
  evaluateInsiderRisk,
  startMonitoring,
  evaluateSession,
};
