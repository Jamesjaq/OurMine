/**
 * @module social_eng
 * Social engineering — phishing email generation, pretexting, vishing scripts,
 * OSINT-personalised lures, and campaign management.
 */

import * as crypto from "node:crypto";

// ─── Types ────────────────────────────────────────────────────────────────────

export type EngagementType = "phishing" | "spear_phishing" | "vishing" | "smishing" | "whaling" | "pretexting";

export interface PhishingEmail {
  id: string;
  type: EngagementType;
  subject: string;
  senderName: string;
  senderEmail: string;
  bodyHtml: string;
  bodyText: string;
  trackingPixel?: string;
  phishingUrl?: string;
  generatedAt: string;
}

export interface VishingScript {
  scenario: string;
  opener: string;
  steps: string[];
  objectionHandlers: Record<string, string>;
  closer: string;
}

export interface CampaignResult {
  campaignId: string;
  sent: number;
  opened: number;
  clicked: number;
  credsCaptured: number;
  timestamp: string;
}

export interface SocialEngOptions {
  live?: boolean;
  targetName?: string;
  targetCompany?: string;
  targetEmail?: string;
  senderDomain?: string;
}

// ─── Phishing templates ───────────────────────────────────────────────────────

type TemplateKey = "it_password_reset" | "hr_benefits" | "ceo_wire" | "sharepoint_file" | "mfa_verify";

const EMAIL_TEMPLATES: Record<TemplateKey, (opts: SocialEngOptions) => Omit<PhishingEmail, "id" | "generatedAt">> = {
  it_password_reset: (o) => ({
    type: "phishing",
    subject: `[Action Required] Your ${o.targetCompany ?? "Company"} password expires in 24 hours`,
    senderName: `${o.targetCompany ?? "IT"} Help Desk`,
    senderEmail: `helpdesk@${o.senderDomain ?? "it-support.com"}`,
    bodyHtml: `<p>Dear ${o.targetName ?? "User"},</p>
<p>Your account password will expire in <strong>24 hours</strong>. Please reset your password immediately to avoid losing access.</p>
<p><a href="${o.live ? "PHISHING_URL" : "https://example.com"}">Reset Password Now</a></p>
<p>IT Security Team<br>${o.targetCompany ?? "Company"}</p>`,
    bodyText: `Your password expires in 24 hours. Reset at: ${"PHISHING_URL"}`,
  }),
  hr_benefits: (o) => ({
    type: "spear_phishing",
    subject: `Open Enrollment Deadline — Action Required by Friday`,
    senderName: `${o.targetCompany ?? "Company"} HR`,
    senderEmail: `benefits@${o.senderDomain ?? "hr-portal.net"}`,
    bodyHtml: `<p>Hi ${o.targetName ?? "there"},</p>
<p>Open enrollment closes this Friday. Log in to confirm your benefits selections before the deadline.</p>
<p><a href="PHISHING_URL">Review My Benefits</a></p>
<p>HR Department<br>${o.targetCompany ?? "Company"}</p>`,
    bodyText: `Open enrollment closes Friday. Log in at: PHISHING_URL`,
  }),
  ceo_wire: (o) => ({
    type: "whaling",
    subject: `Urgent — Confidential Wire Transfer Required`,
    senderName: `CEO - ${o.targetCompany ?? "Company"}`,
    senderEmail: `ceo@${o.senderDomain ?? "ceo-urgent.com"}`,
    bodyHtml: `<p>${o.targetName ?? "Finance team"},</p>
<p>I need you to urgently initiate a wire transfer of $47,500 to close a confidential deal. Please treat this with utmost discretion.</p>
<p>Reply for wire details. I'm in a meeting and reachable only by email.</p>
<p>Best,<br>CEO</p>`,
    bodyText: `Please initiate a $47,500 wire transfer urgently. Reply for details.`,
  }),
  sharepoint_file: (o) => ({
    type: "phishing",
    subject: `${o.targetName ?? "Someone"} shared a file with you: "Q4 Report.xlsx"`,
    senderName: "Microsoft SharePoint",
    senderEmail: `no-reply@${o.senderDomain ?? "sharepoint-notification.com"}`,
    bodyHtml: `<p>${o.targetName ?? "A colleague"} shared a document with you:</p>
<p><a href="PHISHING_URL">📎 Q4_Financial_Report.xlsx</a></p>
<p>Click the link above to view the shared file.</p>
<small>Microsoft SharePoint | Report as spam</small>`,
    bodyText: `View shared file: PHISHING_URL`,
  }),
  mfa_verify: (o) => ({
    type: "phishing",
    subject: `Verify your identity — unusual sign-in activity detected`,
    senderName: `${o.targetCompany ?? "Company"} Security`,
    senderEmail: `security@${o.senderDomain ?? "security-alert.net"}`,
    bodyHtml: `<p>We detected unusual sign-in activity on your account from a new device.</p>
<p>If this was you, no action is needed. If not, please verify your identity immediately:</p>
<p><a href="PHISHING_URL">Verify My Account</a></p>
<p>Security Team<br>${o.targetCompany ?? "Company"}</p>`,
    bodyText: `Unusual activity detected. Verify: PHISHING_URL`,
  }),
};

/**
 * Generate a phishing email from a template.
 */
export function generatePhishingEmail(
  template: TemplateKey,
  opts: SocialEngOptions = {}
): PhishingEmail {
  const builder = EMAIL_TEMPLATES[template];
  const base = builder(opts);
  return {
    ...base,
    id: crypto.randomUUID(),
    generatedAt: new Date().toISOString(),
  };
}

// ─── Vishing scripts ──────────────────────────────────────────────────────────

export function generateVishingScript(
  scenario: "it_support" | "bank_fraud" | "irs" | "tech_support",
  opts: SocialEngOptions = {}
): VishingScript {
  const company = opts.targetCompany ?? "your company";
  const name = opts.targetName ?? "there";

  const scripts: Record<string, VishingScript> = {
    it_support: {
      scenario: "IT Support — MFA seed harvest",
      opener: `Hi, this is ${opts.live ? "Alex" : "[NAME]"} calling from ${company}'s IT support team. May I speak with ${name}?`,
      steps: [
        "Confirm their employee ID for verification.",
        "Explain there's been a security incident and their account needs re-enrollment.",
        "Ask them to read the 6-digit MFA code that appears on their authenticator app.",
        "Use captured code in real-time to log into target account.",
        "Thank them and tell them security re-enrollment is complete.",
      ],
      objectionHandlers: {
        "How do I know you're from IT?": "You can verify by checking the incident ticket I'll send to your email — do you see it?",
        "I'm busy": "I completely understand. This will only take 2 minutes to avoid a potential account lockout.",
        "I'll call IT directly": "Of course, our direct line is [SPOOFED NUMBER]. Ask for incident INC-${Math.floor(Math.random()*99999)}.",
      },
      closer: "Thank you for your co-operation. Your account is now secure. Have a great day!",
    },
    bank_fraud: {
      scenario: "Bank Fraud Detection — credential harvest",
      opener: `Hello, this is the fraud prevention team at ${company} Bank. Is this ${name}?`,
      steps: [
        "Inform them of 'suspicious transactions' on their account.",
        "Ask them to confirm their card number and expiry to 'validate identity'.",
        "Ask for the 3-digit CVV to 'complete verification'.",
        "Ask for the OTP sent to their phone to 'freeze the fraudulent activity'.",
      ],
      objectionHandlers: {
        "I'll call the bank directly": "Please use the number on the back of your card — but act quickly as the account will be suspended in 10 minutes.",
      },
      closer: "Your account has been secured. You should see the block lifted in 24 hours.",
    },
    irs: {
      scenario: "IRS Impersonation — urgency/fear",
      opener: "This message is from the Internal Revenue Service. This call is to notify you of a lawsuit that is being filed against you.",
      steps: [
        "Create urgency — 'law enforcement will visit if payment not made in 45 minutes'.",
        "Demand payment via gift cards or wire transfer.",
        "Collect card numbers and PINs.",
      ],
      objectionHandlers: {
        "I'll call the IRS": "The case number is IRS-${Math.floor(Math.random()*9999999)}. However, calling will not stop the process already in motion.",
      },
      closer: "Your case has been resolved. You will not face further action.",
    },
    tech_support: {
      scenario: "Tech Support Scam — remote access",
      opener: `Hi, this is Microsoft Support calling. We've detected critical errors on your computer, ${name}.`,
      steps: [
        "Tell them their Windows Event Log shows errors (instructs to run eventvwr).",
        "Show them normal errors as 'malware evidence'.",
        "Direct them to install a remote access tool (TeamViewer / AnyDesk).",
        "Use remote session to install implant or harvest credentials.",
      ],
      objectionHandlers: {
        "Microsoft doesn't call people": "You're right that we don't normally call — we only reach out when we detect critical system errors being reported from your IP.",
      },
      closer: "Your computer is now cleaned and protected. Thank you for using Microsoft Support.",
    },
  };

  return scripts[scenario] ?? scripts["it_support"];
}

// ─── SMS phishing ─────────────────────────────────────────────────────────────

export function generateSmishingMessage(
  scenario: "package_delivery" | "bank_alert" | "prize_winner",
  opts: SocialEngOptions = {}
): string {
  const url = "https://short.url/XXXXX";
  const templates: Record<string, string> = {
    package_delivery: `USPS: Your package is pending delivery. Confirm address: ${url}`,
    bank_alert: `${opts.targetCompany ?? "BANK"} ALERT: Unusual activity detected. Verify now: ${url} or call 1-800-XXXXX`,
    prize_winner: `Congratulations! You've been selected for a $500 gift card. Claim now: ${url} (expires 24h)`,
  };
  return templates[scenario] ?? templates["package_delivery"];
}

export default { generatePhishingEmail, generateVishingScript, generateSmishingMessage };
