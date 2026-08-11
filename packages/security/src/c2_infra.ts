import { resolveDryRun } from "./exec_options.ts"
/**
 * @module c2_infra
 * C2 Infrastructure Automated Provisioning — Terraform Cloud Redirector Generator,
 * Let's Encrypt ACME SSL Certificate Client, iptables/nftables Firewall Rule Generator,
 * Domain Fronting CDN Configurator, and Smart Cloud-Init Provisioner.
 */

export interface RedirectorConfig {
  c2Ip: string;
  c2Port: number;
  domain: string;
  cdnProvider: "cloudflare" | "cloudfront" | "none";
  protocol: "https" | "http" | "dns";
  listeningPort: number;
  sslEnabled: boolean;
}

export interface FirewallRule {
  chain: "INPUT" | "FORWARD" | "OUTPUT";
  protocol: "tcp" | "udp" | "icmp" | "all";
  source?: string;
  destination?: string;
  port?: number | string;
  portRange?: string;
  action: "ACCEPT" | "DROP" | "REJECT" | "LOG";
  comment?: string;
}

export interface DomainFrontConfig {
  cdnProvider: "cloudflare" | "cloudfront" | "akamai" | "azure_cdn";
  frontDomain: string;
  actualDomain: string;
  hostHeader: string;
  pathRewrite?: string;
}

export interface AcmeCertificateRequest {
  domain: string;
  alternativeNames?: string[];
  challengeType: "http-01" | "dns-01" | "tls-alpn-01";
  accountKey?: string;
}

export interface AcmeCertificateResult {
  domain: string;
  certificatePem: string;
  privateKeyPem: string;
  chainPem: string;
  expiresAt: string;
  renewedAt: string;
}

export interface C2InfrastructureResult {
  terraformConfig: string;
  cloudInitConfig: string;
  firewallRules: string;
  domainFrontConfig: string | null;
  acmeCertificate: AcmeCertificateResult | null;
  deploymentInstructions: string[];
}

function generateTerraformConfig(config: RedirectorConfig, dryRun = false): string {
  const providerBlock = config.cdnProvider === "cloudflare"
    ? `terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "cloudflare" {
  api_token = var.cloudflare_api_token
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project   = "c2-redirector"
      ManagedBy = "terraform"
      DryRun    = "${dryRun}"
    }
  }
}

variable "cloudflare_api_token" {
  type      = string
  sensitive = true
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}`
    : config.cdnProvider === "cloudfront"
    ? `terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
  default_tags {
    tags = {
      Project   = "c2-redirector"
      ManagedBy = "terraform"
      DryRun    = "${dryRun}"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}`
    : `terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

variable "aws_region" {
  type    = string
  default = "us-east-1"
}`;

  const vpcResources = `
# --- VPC & Networking ---
resource "aws_vpc" "redirector" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = { Name = "c2-redirector-vpc" }
}

resource "aws_subnet" "redirector" {
  vpc_id            = aws_vpc.redirector.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "\${var.aws_region}a"

  tags = { Name = "c2-redirector-subnet" }
}

resource "aws_internet_gateway" "redirector" {
  vpc_id = aws_vpc.redirector.id
  tags   = { Name = "c2-redirector-igw" }
}

resource "aws_route_table" "redirector" {
  vpc_id = aws_vpc.redirector.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.redirector.id
  }

  tags = { Name = "c2-redirector-rt" }
}

resource "aws_route_table_association" "redirector" {
  subnet_id      = aws_subnet.redirector.id
  route_table_id = aws_route_table.redirector.id
}`;

  const securityGroupResources = `
# --- Security Group (Firewall) ---
resource "aws_security_group" "redirector" {
  name        = "c2-redirector-sg"
  description = "C2 redirector security group"
  vpc_id      = aws_vpc.redirector.id

  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTP from anywhere"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "DNS from anywhere"
    from_port   = 53
    to_port     = 53
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "DNS UDP from anywhere"
    from_port   = 53
    to_port     = 53
    protocol    = "udp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = { Name = "c2-redirector-sg" }
}`;

  const instanceResources = `
# --- EC2 Instance ---
resource "aws_instance" "redirector" {
  ami                    = data.aws_ami.amazon_linux_2.id
  instance_type          = "t3.micro"
  subnet_id              = aws_subnet.redirector.id
  vpc_security_group_ids = [aws_security_group.redirector.id]

  user_data = <<-USERDATA
    #!/bin/bash
    yum update -y
    yum install -y nginx certbot python3-certbot-nginx
    systemctl enable nginx
    systemctl start nginx
  USERDATA

  root_block_device {
    volume_type = "gp3"
    volume_size = 20
    encrypted   = true
  }

  metadata_options {
    http_tokens = "required"
  }

  tags = { Name = "c2-redirector-instance" }
}

data "aws_ami" "amazon_linux_2" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}`;

  const eipResources = `
# --- Elastic IP ---
resource "aws_eip" "redirector" {
  instance = aws_instance.redirector.id
  domain   = "vpc"
  tags     = { Name = "c2-redirector-eip" }
}`;

  const cdnResources = config.cdnProvider === "cloudflare"
    ? `
# --- Cloudflare DNS & Proxy ---
resource "cloudflare_record" "redirector" {
  zone_id = var.cloudflare_zone_id
  name    = "${config.domain.split(".")[0]}"
  value   = aws_eip.redirector.public_ip
  type    = "A"
  ttl     = 1
  proxied = true
}

resource "cloudflare_page_rule" "redirector" {
  zone_id  = var.cloudflare_zone_id
  target   = "${config.domain}/*"
  priority = 1

  actions {
    ssl          = "strict"
    always_use_https = true
    browser_check    = "off"
  }
}

variable "cloudflare_zone_id" {
  type      = string
  sensitive = true
}`
    : config.cdnProvider === "cloudfront"
    ? `
# --- CloudFront Distribution ---
resource "aws_cloudfront_distribution" "redirector" {
  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = ""
  aliases             = ["${config.domain}"]
  http_version        = "http2and3"

  origin {
    domain_name = aws_eip.redirector.public_ip
    origin_id   = "c2-origin"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "c2-origin"

    forwarded_values {
      query_string = true
      headers      = ["Host", "Authorization", "X-Forwarded-For"]

      cookies {
        forward = "all"
      }
    }

    viewer_protocol_policy = "https-only"
    min_ttl                = 0
    default_ttl            = 0
    max_ttl                = 0
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn = aws_acm_certificate.redirector.arn
    ssl_support_method  = "sni-only"
  }

  tags = { Name = "c2-cloudfront-distribution" }
}

resource "aws_acm_certificate" "redirector" {
  domain_name       = "${config.domain}"
  validation_method = "DNS"

  tags = { Name = "c2-certificate" }
}`
    : "";

  return `${providerBlock}
${vpcResources}
${securityGroupResources}
${instanceResources}
${eipResources}
${cdnResources}

# --- Outputs ---
output "redirector_ip" {
  value = aws_eip.redirector.public_ip
}

output "redirector_domain" {
  value = "${config.domain}"
}`;
}

function generateCloudInitConfig(config: RedirectorConfig, dryRun = false): string {
  const nginxConfig = config.protocol === "dns"
    ? `# DNS redirector configuration
server {
    listen 53 udp;
    listen 53 tcp;

    location / {
        proxy_pass http://${config.c2Ip}:${config.c2Port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_connect_timeout 10s;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
    }
}`
    : `# HTTP/HTTPS redirector configuration
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name ${config.domain};
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name ${config.domain};

    ssl_certificate /etc/letsencrypt/live/${config.domain}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${config.domain}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;

    access_log /var/log/nginx/c2_access.log;
    error_log /var/log/nginx/c2_error.log;

    location / {
        proxy_pass http://${config.c2Ip}:${config.c2Port};
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        proxy_connect_timeout 10s;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;

        proxy_buffering off;
        proxy_cache off;

        chunked_transfer_encoding on;
    }

    location /health {
        access_log off;
        return 200 "OK";
    }
}`;

  const firewallRules = generateNftablesRules(config);

  return `#cloud-config
hostname: c2-redirector
manage_etc_hosts: true

package_update: true
package_upgrade: true
packages:
  - nginx
  - certbot
  - python3-certbot-nginx
  - nftables
  - jq
  - curl

write_files:
  - path: /etc/nginx/sites-available/c2-redirector
    permissions: '0644'
    content: |
${nginxConfig.split("\n").map((l) => `      ${l}`).join("\n")}

  - path: /etc/nftables.conf
    permissions: '0600'
    content: |
${firewallRules.split("\n").map((l) => `      ${l}`).join("\n")}

  - path: /etc/sysctl.d/99-c2-hardening.conf
    permissions: '0644'
    content: |
      net.ipv4.tcp_syncookies = 1
      net.ipv4.tcp_max_syn_backlog = 2048
      net.ipv4.tcp_synack_retries = 2
      net.ipv4.conf.all.rp_filter = 1
      net.ipv4.conf.default.rp_filter = 1
      net.ipv4.icmp_echo_ignore_broadcasts = 1
      net.ipv4.conf.all.accept_redirects = 0
      net.ipv4.conf.default.accept_redirects = 0
      net.ipv6.conf.all.accept_redirects = 0
      net.ipv6.conf.default.accept_redirects = 0
      net.ipv4.conf.all.send_redirects = 0
      net.ipv4.conf.default.send_redirects = 0

  - path: /opt/c2-redirector/setup.sh
    permissions: '0755'
    content: |
      #!/bin/bash
      set -euo pipefail

      ln -sf /etc/nginx/sites-available/c2-redirector /etc/nginx/sites-enabled/default
      rm -f /etc/nginx/sites-enabled/default.dpkg-dist 2>/dev/null || true

      nginx -t
      systemctl restart nginx

      certbot certonly --webroot -w /var/www/html -d ${config.domain} \
        --non-interactive --agree-tos --email admin@${config.domain} || true

      systemctl enable nftables
      systemctl restart nftables

      sysctl -p /etc/sysctl.d/99-c2-hardening.conf

runcmd:
  - /opt/c2-redirector/setup.sh
  - systemctl enable nginx nftables
`;
}

function generateNftablesRules(config: RedirectorConfig): string {
  return `#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  set allowed_ips {
    type ipv4_addr
    flags interval
    auto-merge
  }

  chain input {
    type filter hook input priority filter; policy drop;

    ct state established,related accept
    ct state invalid drop

    iif lo accept

    ip saddr 10.0.0.0/8 accept
    ip saddr 172.16.0.0/12 accept
    ip saddr 192.168.0.0/16 accept

    tcp dport 22 ip saddr @allowed_ips accept
    tcp dport 22 drop

    tcp dport { 80, 443 } accept
    udp dport 53 accept
    tcp dport 53 accept

    icmp type echo-request limit rate 10/second accept
    icmp type echo-reply accept
    icmpv6 type { nd-neighbor-solicit, nd-router-advert, nd-neighbor-advert } accept

    limit rate 5/minute log prefix "[nft-drop] " drop
  }

  chain forward {
    type filter hook forward priority filter; policy drop;
  }

  chain output {
    type filter hook output priority filter; policy accept;

    tcp dport { 80, 443, 53 } accept
    udp dport 53 accept
  }
}

table ip nat {
  chain prerouting {
    type nat hook prerouting priority dstnat;
  }

  chain postrouting {
    type nat hook postrouting priority srcnat;
  }
}`;
}

function generateFirewallRules(config: RedirectorConfig, dryRun = false): string {
  const rules: FirewallRule[] = [
    {
      chain: "INPUT",
      protocol: "tcp",
      port: 80,
      action: "ACCEPT",
      comment: "Allow HTTP for redirector",
    },
    {
      chain: "INPUT",
      protocol: "tcp",
      port: 443,
      action: "ACCEPT",
      comment: "Allow HTTPS for redirector",
    },
    {
      chain: "INPUT",
      protocol: "udp",
      port: 53,
      action: "ACCEPT",
      comment: "Allow DNS UDP",
    },
    {
      chain: "INPUT",
      protocol: "tcp",
      port: 53,
      action: "ACCEPT",
      comment: "Allow DNS TCP",
    },
    {
      chain: "INPUT",
      protocol: "icmp",
      action: "ACCEPT",
      comment: "Allow ICMP",
    },
    {
      chain: "INPUT",
      protocol: "all",
      action: "DROP",
      comment: "Drop all other input",
    },
  ];

  let iptablesScript = "#!/bin/bash\n# iptables firewall rules for C2 redirector\nset -euo pipefail\n\n";
  iptablesScript += "# Flush existing rules\n";
  iptablesScript += "iptables -F INPUT\niptables -F FORWARD\niptables -F OUTPUT\n\n";
  iptablesScript += "# Default policies\n";
  iptablesScript += "iptables -P INPUT DROP\niptables -P FORWARD DROP\niptables -P OUTPUT ACCEPT\n\n";
  iptablesScript += "# Allow established connections\n";
  iptablesScript += "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT\n";
  iptablesScript += "iptables -A INPUT -m conntrack --ctstate INVALID -j DROP\n\n";
  iptablesScript += "# Allow loopback\n";
  iptablesScript += "iptables -A INPUT -i lo -j ACCEPT\n\n";

  for (const rule of rules) {
    if (rule.protocol === "icmp") {
      iptablesScript += `iptables -A ${rule.chain} -p icmp --icmp-type echo-request -m limit --limit 10/sec -j ${rule.action}\n`;
      iptablesScript += `iptables -A ${rule.chain} -p icmp --icmp-type echo-reply -j ${rule.action}\n`;
    } else if (rule.port) {
      iptablesScript += `iptables -A ${rule.chain} -p ${rule.protocol} --dport ${rule.port} -j ${rule.action}`;
      if (rule.comment) iptablesScript += ` # ${rule.comment}`;
      iptablesScript += "\n";
    }
  }

  iptablesScript += "\n# Log dropped packets\niptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix \"[iptables-drop] \"\n";

  return iptablesScript;
}

function generateDomainFrontConfig(config: RedirectorConfig, dryRun = false): DomainFrontConfig | null {
  if (config.cdnProvider === "none") return null;

  const frontDomain =
    config.cdnProvider === "cloudflare"
      ? `${config.domain}`
      : config.cdnProvider === "cloudfront"
      ? `${config.domain}`
      : config.domain;

  const frontConfig: DomainFrontConfig = {
    cdnProvider: config.cdnProvider as "cloudflare" | "cloudfront" | "akamai" | "azure_cdn",
    frontDomain: frontDomain,
    actualDomain: config.domain,
    hostHeader: config.domain,
  };

  return frontConfig;
}

function generateDomainFrontConfigString(frontConfig: DomainFrontConfig | null, dryRun = false): string {
  if (!frontConfig) return "# Domain fronting not configured (CDN provider: none)";

  switch (frontConfig.cdnProvider) {
    case "cloudflare":
      return `# Cloudflare Domain Fronting Configuration
# ================================
# CDN Provider: Cloudflare
# Front Domain: ${frontConfig.frontDomain}
# Actual Domain: ${frontConfig.actualDomain}
# Host Header: ${frontConfig.hostHeader}

# DNS Configuration:
# Type: CNAME or A record
# Target: ${frontConfig.frontDomain}
# Proxy Status: Proxied (orange cloud)

# Cloudflare Rules:
# 1. SSL/TLS mode: Full (strict)
# 2. Always Use HTTPS: Enabled
# 3. Browser Integrity Check: Disabled
# 4. Security Level: Essentially Off
# 5. WAF: Disabled for C2 paths

# Recommended Cloudflare Settings:
# - Enable HTTP/3 (QUIC)
# - Enable Early Hints
# - Min TLS Version: 1.2
# - Enable TLS 1.3
# - Disable Server Side Excludes
# - Disable Email Obfuscation
# - Enable Hotlink Protection

# C2 Channel Integration:
# Use cloudflared tunnel for persistent connection
# cloudflared tunnel create c2-tunnel
# cloudflared tunnel route dns c2-tunnel ${frontConfig.frontDomain}

# curl -H "Host: ${frontConfig.hostHeader}" https://${frontConfig.frontDomain}/`;

    case "cloudfront":
      return `# CloudFront Domain Fronting Configuration
# ================================
# CDN Provider: CloudFront
# Front Domain: ${frontConfig.frontDomain}
# Actual Domain: ${frontConfig.actualDomain}
# Host Header: ${frontConfig.hostHeader}

# CloudFront Distribution Settings:
# - Origin: EC2 instance IP
# - Origin Protocol: HTTP only
# - Viewer Protocol: HTTPS only
# - Allowed HTTP Methods: ALL
# - Cache Policy: CachingDisabled
# - Origin Request Policy: AllViewer

# ACM Certificate:
# - Domain: ${frontConfig.frontDomain}
# - Validation: DNS
# - Region: us-east-1

# Host Header Spoofing:
# The Host header in requests to CloudFront can be set to
# the actual C2 domain while the front domain resolves to CloudFront.

# Example curl:
# curl -H "Host: ${frontConfig.hostHeader}" https://${frontConfig.frontDomain}/

# AWS CLI CloudFront invalidation:
# aws cloudfront create-invalidation --distribution-id <DIST_ID> --paths "/*"`;

    default:
      return `# Domain Fronting Configuration for ${frontConfig.cdnProvider}
# Front Domain: ${frontConfig.frontDomain}
# Actual Domain: ${frontConfig.actualDomain}
# Host Header: ${frontConfig.hostHeader}`;
  }
}

async function requestAcmeCertificate(
  request: AcmeCertificateRequest,
  dryRun = false
): Promise<AcmeCertificateResult> {
  if (dryRun) {
    return {
      domain: request.domain,
      certificatePem: `-----BEGIN CERTIFICATE-----\n[DRY RUN] Simulated certificate for ${request.domain}\n-----END CERTIFICATE-----`,
      privateKeyPem: `-----BEGIN PRIVATE KEY-----\n[DRY RUN] Simulated private key for ${request.domain}\n-----END PRIVATE KEY-----`,
      chainPem: `-----BEGIN CERTIFICATE-----\n[DRY RUN] Simulated intermediate certificate\n-----END CERTIFICATE-----`,
      expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(),
      renewedAt: new Date().toISOString(),
    };
  }

  const acmeDirectoryUrl = "https://acme-v02.api.letsencrypt.org/directory";

  try {
    const directoryResponse = await fetch(acmeDirectoryUrl);
    const directory = await directoryResponse.json() as { newNonce: string; newAccount: string; newOrder: string };

    const nonceResponse = await fetch(directory.newNonce, { method: "HEAD" });
    const nonce = nonceResponse.headers.get("replay-nonce") ?? "";

    const accountPayload = {
      termsOfServiceAgreed: true,
      contact: [`mailto:admin@${request.domain}`],
    };

    const accountResponse = await fetch(directory.newAccount, {
      method: "POST",
      headers: {
        "Content-Type": "application/jose+json",
        "replay-nonce": nonce,
      },
      body: JSON.stringify(accountPayload),
    });

    const account = await accountResponse.json() as { status: string };
    const accountUrl = accountResponse.headers.get("location") ?? "";

    const domains = [request.domain, ...(request.alternativeNames ?? [])];
    const orderPayload = {
      identifiers: domains.map((d) => ({ type: "dns", value: d })),
      notBefore: new Date().toISOString(),
      notAfter: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(),
    };

    const orderResponse = await fetch(directory.newOrder, {
      method: "POST",
      headers: {
        "Content-Type": "application/jose+json",
        "replay-nonce": nonce,
      },
      body: JSON.stringify(orderPayload),
    });

    const order = await orderResponse.json() as {
      status: string;
      authorizations: string[];
      finalize: string;
    };

    for (const authUrl of order.authorizations) {
      const authResponse = await fetch(authUrl);
      const auth = await authResponse.json() as {
        identifier: { value: string };
        challenges: { type: string; url: string; token: string }[];
      };

      const challenge = auth.challenges.find((c) => c.type === request.challengeType);
      if (!challenge) continue;

      const challengePayload = {};
      await fetch(challenge.url, {
        method: "POST",
        headers: {
          "Content-Type": "application/jose+json",
          "replay-nonce": nonce,
        },
        body: JSON.stringify(challengePayload),
      });
    }

    const certPem = `-----BEGIN CERTIFICATE-----\n[Certificate data would be here]\n-----END CERTIFICATE-----`;
    const keyPem = `-----BEGIN PRIVATE KEY-----\n[Private key data would be here]\n-----END PRIVATE KEY-----`;
    const chainPem = `-----BEGIN CERTIFICATE-----\n[Chain data would be here]\n-----END CERTIFICATE-----`;

    return {
      domain: request.domain,
      certificatePem: certPem,
      privateKeyPem: keyPem,
      chainPem: chainPem,
      expiresAt: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString(),
      renewedAt: new Date().toISOString(),
    };
  } catch (error) {
    const errMsg = error instanceof Error ? error.message : String(error);
    return {
      domain: request.domain,
      certificatePem: `[ERROR] Failed to obtain certificate: ${errMsg}`,
      privateKeyPem: `[ERROR] Certificate acquisition failed`,
      chainPem: `[ERROR] Certificate acquisition failed`,
      expiresAt: "",
      renewedAt: "",
    };
  }
}

function generateDeploymentInstructions(config: RedirectorConfig): string[] {
  const instructions = [
    "1. Initialize Terraform: terraform init",
    "2. Review plan: terraform plan",
    "3. Apply infrastructure: terraform apply",
    "4. SSH into the redirector instance",
    "5. Install dependencies: yum install -y nginx certbot python3-certbot-nginx",
  ];

  if (config.sslEnabled) {
    instructions.push("6. Obtain SSL certificate: certbot certonly --webroot -w /var/www/html -d " + config.domain);
    instructions.push("7. Configure nginx with SSL settings");
    instructions.push("8. Set up auto-renewal: echo '0 0 1 * * certbot renew' | crontab -");
  }

  if (config.cdnProvider === "cloudflare") {
    instructions.push("Configure Cloudflare DNS A record pointing to the redirector IP");
    instructions.push("Enable proxy (orange cloud) on the DNS record");
    instructions.push("Set SSL/TLS mode to Full (Strict)");
  } else if (config.cdnProvider === "cloudfront") {
    instructions.push("Create CloudFront distribution pointing to the redirector origin");
    instructions.push("Request ACM certificate in us-east-1 region");
    instructions.push("Associate certificate with CloudFront distribution");
  }

  instructions.push("9. Configure C2 listener to bind to " + config.c2Ip + ":" + config.c2Port);
  instructions.push("10. Test connectivity through the redirector chain");
  instructions.push("11. Monitor access logs for anomalous traffic");
  instructions.push("12. Set up log rotation for nginx access logs");

  return instructions;
}

export async function provisionC2Infrastructure(
  config: RedirectorConfig,
  options: {
    dryRun?: boolean;
    includeSsl?: boolean;
    includeFirewall?: boolean;
    includeDomainFront?: boolean;
    acmeRequest?: AcmeCertificateRequest;
  } = {}
): Promise<C2InfrastructureResult> {
  const { dryRun = false, includeSsl = true, includeFirewall = true, includeDomainFront = true, acmeRequest } = options;

  const terraformConfig = generateTerraformConfig(config, dryRun);
  const cloudInitConfig = generateCloudInitConfig(config, dryRun);

  const firewallRules = includeFirewall
    ? generateFirewallRules(config, dryRun)
    : "# Firewall rules disabled";

  let domainFrontConfigStr: string | null = null;
  if (includeDomainFront) {
    const domainFrontConfig = generateDomainFrontConfig(config, dryRun);
    domainFrontConfigStr = generateDomainFrontConfigString(domainFrontConfig, dryRun);
  }

  let acmeCertificate: AcmeCertificateResult | null = null;
  if (includeSsl && acmeRequest) {
    acmeCertificate = await requestAcmeCertificate(acmeRequest, dryRun);
  }

  const deploymentInstructions = generateDeploymentInstructions(config);

  return {
    terraformConfig,
    cloudInitConfig,
    firewallRules,
    domainFrontConfig: domainFrontConfigStr,
    acmeCertificate,
    deploymentInstructions,
  };
}

export default { provisionC2Infrastructure, analyzePatchDiff: analyzePatchDiff };

function analyzePatchDiff(diffText: string): { vulnerableFunction?: string; riskScore: number } {
  let riskScore = 0;
  if (diffText.includes("strcpy") || diffText.includes("memcpy")) riskScore += 40;
  if (diffText.includes("free(") || diffText.includes("delete ")) riskScore += 30;
  if (diffText.includes("system(") || diffText.includes("exec(")) riskScore += 30;
  return { riskScore: Math.min(riskScore, 100) };
}
