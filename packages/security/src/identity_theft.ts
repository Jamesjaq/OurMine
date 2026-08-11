/**
 * @module identity_theft
 * Identity Theft & PII Harvesting Simulator — PII Sanitizer & Masker, Dark Web Leak Correlator,
 * SSN/SIN Format Verifier, and Synthetic Identity Detection Engine.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as crypto from "node:crypto";

export interface PIIMatch {
  type: "email" | "ssn" | "sin" | "credit_card" | "phone" | "ip_address" | "name" | "dob" | "address" | "passport";
  value: string;
  start: number;
  end: number;
  masked: string;
  luhnValid?: boolean;
}

export interface IdentityScanResult {
  inputText: string;
  matches: PIIMatch[];
  totalMatches: number;
  categories: Record<string, number>;
  dryRun: boolean;
}

export interface SyntheticIdentity {
  fullName: string;
  ssn: string;
  dob: string;
  address: string;
  phone: string;
  email: string;
  creditScore: number;
  isSynthetic: boolean;
  confidenceScore: number;
  flags: string[];
  dryRun: boolean;
}

export interface BreachCheckResult {
  email: string;
  found: boolean;
  breachCount: number;
  breaches: { name: string; date: string; dataClasses: string[] }[];
  dryRun: boolean;
}

const SSN_REGEX = /\b\d{3}-?\d{2}-?\d{4}\b/g;
const SIN_REGEX = /\b\d{3}[\s-]?\d{3}[\s-]?\d{3}\b/g;
const EMAIL_REGEX = /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g;
const PHONE_REGEX = /\b(?:\+?1[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b/g;
const IP_REGEX = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
const CC_REGEX = /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})\b/g;
const DOB_REGEX = /\b(?:0[1-9]|1[0-2])[\/\-](?:0[1-9]|[12]\d|3[01])[\/\-](?:19|20)\d{2}\b/g;
const PASSPORT_REGEX = /\b[A-Z]{1,2}\d{6,9}\b/g;
const US_ADDR_REGEX = /\b\d{1,5}\s+(?:[A-Z][a-zA-Z]+\s?){1,5}(?:St(?:reet)?|Ave(?:nue)?|Blvd|Boulevard|Dr(?:ive)?|Rd|Road|Way|Ln|Lane|Ct|Court|Pl(?:ace)?|Pkwy|Parkway)\b/g;

function luhnCheck(num: string): boolean {
  const digits = num.replace(/\D/g, "");
  let sum = 0;
  let alternate = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = parseInt(digits[i], 10);
    if (alternate) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    alternate = !alternate;
  }
  return sum % 10 === 0;
}

function maskEmail(email: string): string {
  const [local, domain] = email.split("@");
  if (!local || !domain) return "[EMAIL_MASKED]";
  const masked = local[0] + "***" + local[local.length - 1];
  return masked + "@" + domain;
}

function maskSSN(ssn: string): string {
  return "XXX-XX-" + ssn.replace(/\D/g, "").slice(-4);
}

function maskSIN(sin: string): string {
  return "XXX-XXX-" + sin.replace(/\D/g, "").slice(-3);
}

function maskPhone(phone: string): string {
  const digits = phone.replace(/\D/g, "");
  if (digits.length >= 10) return "XXX-XXX-" + digits.slice(-4);
  return "[PHONE_MASKED]";
}

function maskCC(cc: string): string {
  const digits = cc.replace(/\D/g, "");
  if (digits.length >= 4) return "XXXX-XXXX-XXXX-" + digits.slice(-4);
  return "[CC_MASKED]";
}

function maskIP(ip: string): string {
  return ip.replace(/\d+$/, "XXX");
}

function maskName(name: string): string {
  const parts = name.split(/\s+/);
  return parts.map(p => p[0] + "*".repeat(Math.max(0, p.length - 1))).join(" ");
}

function maskDOB(dob: string): string {
  return "**/**/****";
}

function maskPassport(pass: string): string {
  return pass[0] + "*".repeat(pass.length - 1);
}

function maskAddress(addr: string): string {
  return addr.replace(/^\d+/, "XXX");
}

function getMasker(type: PIIMatch["type"]): (val: string) => string {
  const maskers: Record<string, (val: string) => string> = {
    email: maskEmail,
    ssn: maskSSN,
    sin: maskSIN,
    phone: maskPhone,
    credit_card: maskCC,
    ip_address: maskIP,
    name: maskName,
    dob: maskDOB,
    address: maskAddress,
    passport: maskPassport,
  };
  return maskers[type] || (() => "[MASKED]");
}

export function detectPII(text: string, dryRun = true): IdentityScanResult {
  const matches: PIIMatch[] = [];
  const seen = new Set<string>();

  const patterns: { regex: RegExp; type: PIIMatch["type"] }[] = [
    { regex: CC_REGEX, type: "credit_card" },
    { regex: SSN_REGEX, type: "ssn" },
    { regex: SIN_REGEX, type: "sin" },
    { regex: EMAIL_REGEX, type: "email" },
    { regex: PHONE_REGEX, type: "phone" },
    { regex: IP_REGEX, type: "ip_address" },
    { regex: DOB_REGEX, type: "dob" },
    { regex: PASSPORT_REGEX, type: "passport" },
    { regex: US_ADDR_REGEX, type: "address" },
  ];

  for (const { regex, type } of patterns) {
    const re = new RegExp(regex.source, regex.flags);
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) {
      const value = m[0];
      const key = `${type}:${value}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const luhnValid = type === "credit_card" ? luhnCheck(value) : undefined;
      matches.push({
        type,
        value,
        start: m.index,
        end: m.index + value.length,
        masked: getMasker(type)(value),
        luhnValid,
      });
    }
  }

  matches.sort((a, b) => a.start - b.start);
  const categories: Record<string, number> = {};
  for (const m of matches) categories[m.type] = (categories[m.type] || 0) + 1;

  return { inputText: text, matches, totalMatches: matches.length, categories, dryRun };
}

export function maskPII(text: string, dryRun = true): string {
  const result = detectPII(text, dryRun);
  let masked = text;
  for (let i = result.matches.length - 1; i >= 0; i--) {
    const m = result.matches[i];
    masked = masked.substring(0, m.start) + m.masked + masked.substring(m.end);
  }
  return masked;
}

export function validateSSN(ssn: string): { valid: boolean; formatted: string; region: string } {
  const digits = ssn.replace(/\D/g, "");
  if (digits.length !== 9) return { valid: false, formatted: "", region: "INVALID" };

  const area = parseInt(digits.substring(0, 3), 10);
  const group = parseInt(digits.substring(3, 5), 10);
  const serial = parseInt(digits.substring(5, 9), 10);

  if (area === 0 || area === 666 || area >= 900) return { valid: false, formatted: "", region: "INVALID" };
  if (group === 0 || serial === 0) return { valid: false, formatted: "", region: "INVALID" };

  const region = area < 200 ? "NH, ME, VT, MA, RI, CT"
    : area < 300 ? "NY, NJ"
    : area < 400 ? "PA, DE, MD"
    : area < 500 ? "DC, VA, WV, NC, SC"
    : area < 600 ? "FL, GA, AL, MS, TN, AR, LA"
    : area < 700 ? "OH, IN, KY, MI, WI"
    : area < 800 ? "IL, MN, IA, MO, ND, SD, NE, KS"
    : area < 900 ? "MT, ID, WY, CO, NM, OK, TX, UT, AZ"
    : "CA, OR, WA, AK, HI";

  return { valid: true, formatted: `${digits.substring(0, 3)}-${digits.substring(3, 5)}-${digits.substring(5)}`, region };
}

export function validateSIN(sin: string): { valid: boolean; formatted: string } {
  const digits = sin.replace(/\D/g, "");
  if (digits.length !== 9) return { valid: false, formatted: "" };

  const weighted = [1, 2, 1, 2, 1, 2, 1, 2, 1];
  let sum = 0;
  for (let i = 0; i < 9; i++) {
    let d = parseInt(digits[i], 10) * weighted[i];
    if (d > 9) d -= 9;
    sum += d;
  }
  const valid = sum % 10 === 0;
  return { valid, formatted: valid ? `${digits.substring(0, 3)}-${digits.substring(3, 6)}-${digits.substring(6)}` : "" };
}

export function validateCreditCard(number: string): { valid: boolean; brand: string; formatted: string } {
  const digits = number.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return { valid: false, brand: "UNKNOWN", formatted: "" };

  let brand = "UNKNOWN";
  if (/^4/.test(digits)) brand = "VISA";
  else if (/^5[1-5]/.test(digits)) brand = "MASTERCARD";
  else if (/^3[47]/.test(digits)) brand = "AMEX";
  else if (/^6011/.test(digits) || /^65/.test(digits)) brand = "DISCOVER";
  else if (/^3(?:0[0-5]|[68])/.test(digits)) brand = "DINERS_CLUB";
  else if (/(?:2131|1800|35\d{3})/.test(digits)) brand = "JCB";

  const valid = luhnCheck(digits);
  const groups = digits.match(/.{1,4}/g);
  const formatted = groups ? groups.join("-") : digits;

  return { valid, brand, formatted };
}

export function generateSyntheticIdentity(dryRun = true): SyntheticIdentity {
  const firstNames = ["James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda", "David", "Elizabeth", "William", "Barbara", "Richard", "Susan", "Joseph", "Jessica", "Thomas", "Sarah", "Christopher", "Karen"];
  const lastNames = ["Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas", "Taylor", "Moore", "Jackson", "Martin"];
  const streets = ["Maple St", "Oak Ave", "Pine Rd", "Elm Dr", "Cedar Ln", "Birch Way", "Walnut Ct", "1st Ave", "Main St", "Park Blvd"];
  const cities = ["Springfield", "Riverside", "Fairview", "Greenville", "Bristol", "Clinton", "Georgetown", "Salem", "Madison", "Manchester"];

  const firstName = firstNames[Math.floor(Math.random() * firstNames.length)];
  const lastName = lastNames[Math.floor(Math.random() * lastNames.length)];
  const streetNum = Math.floor(Math.random() * 9999) + 1;
  const street = streets[Math.floor(Math.random() * streets.length)];
  const city = cities[Math.floor(Math.random() * cities.length)];
  const stateCode = ["AL","AK","AZ","AR","CA","CO","CT","DE","FL","GA","HI","ID","IL","IN","IA","KS","KY","LA","ME","MD","MA","MI","MN","MS","MO","MT","NE","NV","NH","NJ","NM","NY","NC","ND","OH","OK","OR","PA","RI","SC","SD","TN","TX","UT","VT","VA","WA","WV","WI","WY"][Math.floor(Math.random() * 50)];
  const zip = String(Math.floor(Math.random() * 90000) + 10000);

  const year = 1950 + Math.floor(Math.random() * 50);
  const month = String(Math.floor(Math.random() * 12) + 1).padStart(2, "0");
  const day = String(Math.floor(Math.random() * 28) + 1).padStart(2, "0");

  const area = 200 + Math.floor(Math.random() * 800);
  const prefix = Math.floor(Math.random() * 900) + 100;
  const line = Math.floor(Math.random() * 9000) + 1000;

  const ssnArea = 200 + Math.floor(Math.random() * 700);
  const ssnGroup = Math.floor(Math.random() * 99) + 1;
  const ssnSerial = Math.floor(Math.random() * 9999) + 1;
  const ssn = `${ssnArea}-${String(ssnGroup).padStart(2, "0")}-${String(ssnSerial).padStart(4, "0")}`;

  const domain = ["gmail.com", "yahoo.com", "outlook.com", "protonmail.com"][Math.floor(Math.random() * 4)];
  const email = `${firstName.toLowerCase()}.${lastName.toLowerCase()}${Math.floor(Math.random() * 999)}@${domain}`;

  const creditScore = 300 + Math.floor(Math.random() * 550);

  const flags: string[] = [];
  if (creditScore < 500) flags.push("VERY_LOW_CREDIT_SCORE");
  if (ssnArea >= 900) flags.push("INVALID_SSN_RANGE");
  const zipNum = parseInt(zip, 10);
  if (zipNum > 96799 && zipNum < 96898) flags.push("INVALID_ZIP_RANGE");

  return {
    fullName: `${firstName} ${lastName}`,
    ssn,
    dob: `${month}/${day}/${year}`,
    address: `${streetNum} ${street}, ${city}, ${stateCode} ${zip}`,
    phone: `${area}-${prefix}-${line}`,
    email,
    creditScore,
    isSynthetic: true,
    confidenceScore: flags.length > 0 ? 0.95 : 0.75,
    flags,
    dryRun,
  };
}

export async function checkBreach(email: string, dryRun = true): Promise<BreachCheckResult> {
  if (dryRun) {
    return {
      email,
      found: false,
      breachCount: 0,
      breaches: [],
      dryRun: true,
    };
  }

  try {
    const sha1 = crypto.createHash("sha1").update(email.toLowerCase().trim()).digest("hex").toUpperCase();
    const prefix = sha1.substring(0, 5);
    const suffix = sha1.substring(5);

    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      headers: { "Add-Padding": "true" },
    });
    const text = await res.text();
    const lines = text.split("\n");
    for (const line of lines) {
      const [hashSuffix, count] = line.split(":");
      if (hashSuffix?.trim() === suffix) {
        return {
          email,
          found: parseInt(count.trim(), 10) > 0,
          breachCount: parseInt(count.trim(), 10),
          breaches: [],
          dryRun: false,
        };
      }
    }
    return { email, found: false, breachCount: 0, breaches: [], dryRun: false };
  } catch {
    return { email, found: false, breachCount: 0, breaches: [], dryRun: false };
  }
}

export default { maskPII, detectPII, validateSSN, validateSIN, validateCreditCard, generateSyntheticIdentity, checkBreach };
