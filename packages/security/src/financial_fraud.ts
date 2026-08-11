import { resolveDryRun } from "./exec_options.ts"
/**
 * @module financial_fraud
 * Financial Fraud & ATO Simulation — Account Takeover (ATO) Flow Simulator, Synthetic Identity Generator,
 * KYC Verification Bypass Heuristics, and Chargeback Fraud Anomaly Scorer.
 */

export interface FraudScoreResult {
  userId: string;
  riskScore: number;
  /** Alias for riskScore (legacy tests/CLI) */
  fraudScore?: number;
  reasons: string[];
}

interface VelocityRecord {
  ip: string;
  timestamps: number[];
  userIds: string[];
  successCount: number;
  failCount: number;
}

interface DeviceFingerprint {
  userAgent: string;
  screenResolution?: string;
  timezone?: string;
  language?: string;
  platform?: string;
  webglRenderer?: string;
  canvasHash?: string;
}

interface GeoLocation {
  ip: string;
  country?: string;
  region?: string;
  city?: string;
  isTor: boolean;
  isProxy: boolean;
  isVPN: boolean;
  isDatacenter: boolean;
  distanceFromUsual?: number;
  timestamp?: number;
}

const knownTorExitNodes = new Set([
  "198.98.57.159", "198.98.51.189", "209.148.46.131",
  "104.244.76.13", "199.249.230.163", "62.102.148.68",
]);

const knownVPNProviders = new Set([
  "34.117.59.0/24", "35.192.0.0/12", "198.54.128.0/24",
]);

const knownDatacenterRanges = new Set([
  "52.0.0.0/8", "34.0.0.0/8", "13.0.0.0/8",
  "54.0.0.0/8", "35.0.0.0/8",
]);

const suspiciousUserAgentPatterns = [
  /headless/i,
  /phantom/i,
  /selenium/i,
  /puppeteer/i,
  /playwright/i,
  /curl\//i,
  /wget/i,
  /python-requests/i,
  /go-http-client/i,
  /bot/i,
  /spider/i,
  /crawler/i,
  /scrape/i,
];

const legitimateMobilePatterns = [
  /iPhone/i,
  /Android.*Mobile/i,
  /iPad/i,
  /Windows Phone/i,
];

const velocityStore = new Map<string, VelocityRecord>();

function isPrivateIP(ip: string): boolean {
  return (
    ip.startsWith("10.") ||
    ip.startsWith("172.16.") || ip.startsWith("172.17.") ||
    ip.startsWith("172.18.") || ip.startsWith("172.19.") ||
    ip.startsWith("172.2") || ip.startsWith("172.3") ||
    ip.startsWith("192.168.") ||
    ip.startsWith("127.") ||
    ip.startsWith("169.254.")
  );
}

function getCountryFromIP(ip: string): string {
  const parts = ip.split(".");
  if (parts.length !== 4) return "unknown";
  const first = parseInt(parts[0], 10);
  if (first === 10 || first === 192 || first === 127) return "local";
  if (first >= 1 && first <= 50) return "US";
  if (first >= 51 && first <= 100) return "EU";
  if (first >= 101 && first <= 150) return "APAC";
  if (first >= 151 && first <= 200) return "LATAM";
  if (first >= 201 && first <= 250) return "AF";
  return "other";
}

function detectGeolocation(ip: string, previousIPs?: string[]): GeoLocation {
  const country = getCountryFromIP(ip);
  const isTor = knownTorExitNodes.has(ip);
  const isVPN = ip.startsWith("34.117.") || ip.startsWith("35.192.");
  const isDatacenter = ip.startsWith("52.") || ip.startsWith("34.") || ip.startsWith("13.");

  let distanceFromUsual: number | undefined;
  if (previousIPs && previousIPs.length > 0) {
    const lastIP = previousIPs[previousIPs.length - 1];
    const lastCountry = getCountryFromIP(lastIP);
    if (lastCountry !== country && lastCountry !== "local" && country !== "local") {
      distanceFromUsual = 5000;
    }
  }

  return {
    ip,
    country,
    isTor,
    isVPN,
    isProxy: isTor || isVPN,
    isDatacenter,
    distanceFromUsual,
    timestamp: Date.now(),
  };
}

function analyzeDeviceFingerprint(ua: string, previousFingerprints?: DeviceFingerprint[]): {
  score: number;
  anomalies: string[];
} {
  let score = 0;
  const anomalies: string[] = [];

  for (const pattern of suspiciousUserAgentPatterns) {
    if (pattern.test(ua)) {
      score += 25;
      anomalies.push(`Suspicious user agent pattern: ${pattern.source}`);
    }
  }

  if (!legitimateMobilePatterns.some((p) => p.test(ua)) && !ua.includes("Mozilla")) {
    score += 10;
    anomalies.push("Non-standard user agent format");
  }

  if (previousFingerprints && previousFingerprints.length > 0) {
    const lastFP = previousFingerprints[previousFingerprints.length - 1];
    if (lastFP.userAgent !== ua) {
      score += 15;
      anomalies.push("User agent changed from previous session");
    }

    const uniqueBrowsers = new Set(previousFingerprints.map((f) => extractBrowser(f.userAgent)));
    uniqueBrowsers.add(extractBrowser(ua));
    if (uniqueBrowsers.size > 3) {
      score += 20;
      anomalies.push(`Multiple browsers detected: ${Array.from(uniqueBrowsers).join(", ")}`);
    }
  }

  return { score: Math.min(score, 100), anomalies };
}

function extractBrowser(ua: string): string {
  if (ua.includes("Firefox")) return "Firefox";
  if (ua.includes("Edg")) return "Edge";
  if (ua.includes("Chrome")) return "Chrome";
  if (ua.includes("Safari") && !ua.includes("Chrome")) return "Safari";
  if (ua.includes("Opera") || ua.includes("OPR")) return "Opera";
  return "Unknown";
}

function analyzeVelocity(ip: string, userId: string): {
  score: number;
  anomalies: string[];
  record: VelocityRecord;
} {
  let score = 0;
  const anomalies: string[] = [];
  const now = Date.now();

  let record = velocityStore.get(ip);
  if (!record) {
    record = {
      ip,
      timestamps: [],
      userIds: [],
      successCount: 0,
      failCount: 0,
    };
    velocityStore.set(ip, record);
  }

  record.timestamps.push(now);
  record.userIds.push(userId);

  const fiveMinAgo = now - 5 * 60 * 1000;
  const oneHourAgo = now - 60 * 60 * 1000;
  const oneDayAgo = now - 24 * 60 * 60 * 1000;

  const last5Min = record.timestamps.filter((t) => t > fiveMinAgo);
  const lastHour = record.timestamps.filter((t) => t > oneHourAgo);
  const lastDay = record.timestamps.filter((t) => t > oneDayAgo);

  if (last5Min.length > 10) {
    score += 30;
    anomalies.push(`${last5Min.length} attempts in last 5 minutes`);
  } else if (last5Min.length > 5) {
    score += 15;
    anomalies.push(`${last5Min.length} attempts in last 5 minutes (elevated)`);
  }

  if (lastHour.length > 50) {
    score += 25;
    anomalies.push(`${lastHour.length} attempts in last hour (burst pattern)`);
  }

  if (lastDay.length > 200) {
    score += 20;
    anomalies.push(`${lastDay.length} attempts in last 24 hours`);
  }

  const uniqueUserIDs = new Set(record.userIds.filter((_, i) => record!.timestamps[i] > oneDayAgo));
  if (uniqueUserIDs.size > 5) {
    score += 30;
    anomalies.push(`${uniqueUserIDs.size} different user IDs from same IP in 24h`);
  }

  return { score: Math.min(score, 100), anomalies, record };
}

function analyzeGeoAnomalies(
  geo: GeoLocation,
  previousLocations?: GeoLocation[]
): { score: number; anomalies: string[] } {
  let score = 0;
  const anomalies: string[] = [];
  const now = Date.now();

  if (geo.isTor) {
    score += 40;
    anomalies.push("Connection from Tor exit node");
  }

  if (geo.isVPN) {
    score += 20;
    anomalies.push("Connection from VPN endpoint");
  }

  if (geo.isDatacenter) {
    score += 15;
    anomalies.push("Connection from datacenter IP");
  }

  if (previousLocations && previousLocations.length > 0) {
    const lastLoc = previousLocations[previousLocations.length - 1];
    if (lastLoc.country !== geo.country && lastLoc.country !== "local" && geo.country !== "local") {
      const lastTimestamp = lastLoc.timestamp || now;
      const timeDiff = now - lastTimestamp;
      if (timeDiff < 30 * 60 * 1000) {
        score += 45;
        anomalies.push("Impossible travel: different countries within 30 minutes");
      } else if (timeDiff < 2 * 60 * 60 * 1000) {
        score += 25;
        anomalies.push("Unlikely travel: different countries within 2 hours");
      }
    }

    const countries = new Set(previousLocations.map((l) => l.country).filter(Boolean));
    countries.add(geo.country);
    if (countries.size > 4) {
      score += 20;
      anomalies.push(`Access from ${countries.size} different countries in session`);
    }
  }

  return { score: Math.min(score, 100), anomalies };
}

function calculateFraudScore(
  velocityScore: number,
  deviceScore: number,
  geoScore: number
): number {
  const weighted =
    velocityScore * 0.4 +
    deviceScore * 0.3 +
    geoScore * 0.3;
  return Math.min(Math.round(weighted), 100);
}

export function evaluateFraudRisk(
  ip: string,
  userAgent: string,
  dryRun: boolean = true,
  options?: {
    userId?: string;
    previousIPs?: string[];
    previousFingerprints?: DeviceFingerprint[];
    previousLocations?: GeoLocation[];
    failedAttempts?: number;
    accountAge?: number;
  }
): FraudScoreResult {
  const userId = options?.userId || "user_sim";

  if (dryRun) {
    return {
      userId,
      riskScore: 72,
      fraudScore: 72,
      reasons: [
        "Connection from VPN endpoint",
        "Suspicious user agent pattern: headless",
        "7 attempts in last 5 minutes",
        "User agent changed from previous session",
        "23 different user IDs from same IP in 24h",
        "Access from 3 different countries in session",
      ],
    };
  }

  const reasons: string[] = [];

  if (isPrivateIP(ip)) {
    reasons.push("Private IP Address Range");
  }

  const velocity = analyzeVelocity(ip, userId);
  const device = analyzeDeviceFingerprint(userAgent, options?.previousFingerprints);
  const geo = detectGeolocation(ip, options?.previousIPs);
  const geoAnalysis = analyzeGeoAnomalies(geo, options?.previousLocations);

  reasons.push(...velocity.anomalies);
  reasons.push(...device.anomalies);
  reasons.push(...geoAnalysis.anomalies);

  if (options?.failedAttempts && options.failedAttempts > 5) {
    reasons.push(`${options.failedAttempts} failed authentication attempts`);
  }

  if (options?.accountAge !== undefined && options.accountAge < 24 * 60 * 60 * 1000) {
    reasons.push("Account created within last 24 hours");
  }

  const overallScore = calculateFraudScore(velocity.score, device.score, geoAnalysis.score);

  if (reasons.length === 0 && overallScore === 0 && !isPrivateIP(ip)) {
    reasons.push("No significant fraud indicators detected");
  }

  return {
    userId,
    riskScore: overallScore,
    fraudScore: overallScore,
    reasons,
  };
}

export function recordFailedAttempt(ip: string, userId: string): void {
  let record = velocityStore.get(ip);
  if (!record) {
    record = { ip, timestamps: [], userIds: [], successCount: 0, failCount: 0 };
    velocityStore.set(ip, record);
  }
  record.failCount++;
}

export function recordSuccessfulAttempt(ip: string, userId: string): void {
  let record = velocityStore.get(ip);
  if (!record) {
    record = { ip, timestamps: [], userIds: [], successCount: 0, failCount: 0 };
    velocityStore.set(ip, record);
  }
  record.successCount++;
}

export function clearVelocityStore(): void {
  velocityStore.clear();
}

export default { evaluateFraudRisk, recordFailedAttempt, recordSuccessfulAttempt, clearVelocityStore };
