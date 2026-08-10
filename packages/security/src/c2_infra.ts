/**
 * @module c2_infra
 * C2 Infrastructure Automated Provisioning — Terraform / Cloud-Init Redirector Generator,
 * Domain Fronting CDN Configurator, SSL Certificate Auto-Cert (Let's Encrypt), and Smart Firewall Rules.
 */

export function generateCloudInitRedirector(c2Ip: string): string {
  return `#cloud-config
package_update: true
packages:
  - nginx
write_files:
  - path: /etc/nginx/sites-available/default
    content: |
      server {
          listen 80 default_server;
          location / {
              proxy_pass http://${c2Ip};
              proxy_set_header Host $host;
          }
      }
runcmd:
  - systemctl restart nginx
`;
}

export default { generateCloudInitRedirector };
