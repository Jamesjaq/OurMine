/**
 * AD attack-path analysis (port of `modules.ad_engine`).
 *
 * Parses BloodHound CE JSON dumps (nodes + directed edges) into a graph and
 * produces ordered attack paths — Kerberoasting, ACL abuse, DCSync,
 * session/admin pivots — mapped to MITRE ATT&CK techniques. Planner-ready
 * JSON that the execution node turns into HITL-gated actions.
 */

import { readFile } from "node:fs/promises";

// ------------------------------------------------------------------------- //
// Graph model
// ------------------------------------------------------------------------- //

export interface ADNode {
  object_id: string;
  label: string; // User | Group | Computer | Domain
  name: string;
  properties: Record<string, unknown>;

  isUser(): boolean;
  isComputer(): boolean;
  isDomain(): boolean;
  hasSpn(): boolean;
  toDict(): Record<string, unknown>;
}

export function makeADNode(objectId: string, label: string, name: string, properties: Record<string, unknown> = {}): ADNode {
  const node: ADNode = {
    object_id: objectId,
    label,
    name,
    properties,
    isUser() {
      return this.label === "User";
    },
    isComputer() {
      return this.label === "Computer";
    },
    isDomain() {
      return this.label === "Domain";
    },
    hasSpn() {
      return (
        this.isUser() &&
        Boolean(
          this.properties["serviceprincipalnames"] ||
            this.properties["hasSPN"],
        )
      );
    },
    toDict() {
      const allowed = new Set(["enabled", "highvalue", "domain", "admincount", "sessions", "owned"]);
      return {
        object_id: this.object_id,
        label: this.label,
        name: this.name,
        kerberoastable: this.hasSpn(),
        properties: Object.fromEntries(
          Object.entries(this.properties).filter(([k]) => allowed.has(k)),
        ),
      };
    },
  };
  return node;
}

export interface ADEdge {
  source: string;
  target: string;
  label: string;
  toDict(): Record<string, string>;
}

export function makeADEdge(source: string, target: string, label: string): ADEdge {
  return {
    source,
    target,
    label,
    toDict() {
      return { source: this.source, target: this.target, label: this.label };
    },
  };
}

export class BloodHoundGraph {
  nodes = new Map<string, ADNode>();
  edges: ADEdge[] = [];
  private inEdges = new Map<string, ADEdge[]>();
  private outEdges = new Map<string, ADEdge[]>();

  addNode(node: ADNode): void {
    this.nodes.set(node.object_id, node);
  }

  addEdge(edge: ADEdge): void {
    this.edges.push(edge);
    this.outEdges.set(edge.source, [...(this.outEdges.get(edge.source) ?? []), edge]);
    this.inEdges.set(edge.target, [...(this.inEdges.get(edge.target) ?? []), edge]);
  }

  get(objectId: string): ADNode | undefined {
    return this.nodes.get(objectId);
  }

  outgoing(objectId: string): ADEdge[] {
    return this.outEdges.get(objectId) ?? [];
  }

  incoming(objectId: string): ADEdge[] {
    return this.inEdges.get(objectId) ?? [];
  }

  findByName(name: string): ADNode | undefined {
    const lowered = name.toLowerCase();
    for (const node of this.nodes.values()) {
      if (node.name.toLowerCase() === lowered) return node;
    }
    return undefined;
  }

  users(): ADNode[] {
    return [...this.nodes.values()].filter((n) => n.isUser());
  }

  computers(): ADNode[] {
    return [...this.nodes.values()].filter((n) => n.isComputer());
  }

  edgesOf(label: string): ADEdge[] {
    return this.edges.filter((e) => e.label === label);
  }

  summary(): Record<string, unknown> {
    const users = this.users();
    return {
      nodes: this.nodes.size,
      edges: this.edges.length,
      users: users.length,
      computers: this.computers().length,
      kerberoastable: users.filter((n) => n.hasSpn()).length,
      edge_labels: [...new Set(this.edges.map((e) => e.label))].sort(),
    };
  }

  toDict(): Record<string, unknown> {
    return {
      summary: this.summary(),
      nodes: [...this.nodes.values()].map((n) => n.toDict()),
      edges: this.edges.map((e) => e.toDict()),
    };
  }
}

/** Load a BloodHound CE JSON dump (path, raw string, or parsed dict). */
export async function loadBloodHoundDump(data: string | Record<string, unknown>): Promise<BloodHoundGraph> {
  let payload: Record<string, unknown>;
  if (typeof data === "string") {
    let text = data;
    try {
      text = await readFile(data, "utf-8");
    } catch {
      // treat the string as raw JSON text
    }
    payload = JSON.parse(text) as Record<string, unknown>;
  } else {
    payload = data;
  }

  if (payload["data"] && typeof payload["data"] === "object" && !Array.isArray(payload["data"])) {
    payload = payload["data"] as Record<string, unknown>;
  }

  const graph = new BloodHoundGraph();
  const rawNodes = Array.isArray(payload["nodes"]) ? (payload["nodes"] as unknown[]) : [];
  const rawEdges = Array.isArray(payload["edges"]) ? (payload["edges"] as unknown[]) : [];

  for (const raw of rawNodes) {
    const rec = raw as Record<string, unknown>;
    const nodeData = (rec["data"] && typeof rec["data"] === "object" ? rec["data"] : rec) as Record<string, unknown>;
    const objectId = String(
      nodeData["objectid"] ?? nodeData["object_id"] ?? nodeData["id"] ?? "",
    );
    const label = String(nodeData["label"] ?? "");
    const name = String(nodeData["name"] ?? nodeData["samaccountname"] ?? objectId);
    const propsSource = (nodeData["properties"] && typeof nodeData["properties"] === "object"
      ? (nodeData["properties"] as Record<string, unknown>)
      : nodeData) as Record<string, unknown>;
    const props = Object.fromEntries(
      Object.entries(propsSource).filter(([k]) => !["name", "label", "objectid", "object_id"].includes(k)),
    );
    if (objectId) graph.addNode(makeADNode(objectId, label, name, props));
  }

  for (const raw of rawEdges) {
    const rec = raw as Record<string, unknown>;
    const edgeData = (rec["data"] && typeof rec["data"] === "object" ? rec["data"] : rec) as Record<string, unknown>;
    const source = String(edgeData["source"] ?? edgeData["source_node_id"] ?? "");
    const target = String(edgeData["target"] ?? edgeData["target_node_id"] ?? "");
    const label = String(edgeData["label"] ?? edgeData["relationship"] ?? "");
    if (source && target && label) graph.addEdge(makeADEdge(source, target, label));
  }

  return graph;
}

// ------------------------------------------------------------------------- //
// Attack path planning
// ------------------------------------------------------------------------- //

export type EdgeKind = "kerberoast" | "dcsync" | "acl-abuse" | "member-of" | "session" | "admin" | "owned";

const ACL_ABUSE: Record<string, [string, string]> = {
  ForceChangePassword: ["T1098", "force password reset / shadow credentials"],
  GenericAll: ["T1222", "generic all — full object control"],
  GenericWrite: ["T1222", "generic write — attribute tampering"],
  AddMember: ["T1098", "add principal to group"],
  AddKeyCredentialLink: ["T1556.006", "shadow credentials"],
  WriteDacl: ["T1222", "DACL write — grant self rights"],
  Owns: ["T1222", "object ownership"],
  AllowedToAct: ["T1134.002", "resource-based constrained delegation"],
  CanRDP: ["T1021.001", "remote desktop access"],
  AdminTo: ["T1021.002", "local admin on computer"],
};

const PRIVILEGE_ORDER = ["Domain Admins", "Enterprise Admins", "Administrators", "Domain Controllers"];

export interface ADAttackPath {
  name: string;
  kind: EdgeKind;
  source: ADNode;
  target: ADNode;
  technique_id: string;
  detail: string;
  requires_approval: boolean;
  hop_count: number;
  toDict(): Record<string, unknown>;
}

function makeAttackPath(
  name: string,
  kind: EdgeKind,
  source: ADNode,
  target: ADNode,
  techniqueId: string,
  detail: string,
  hopCount = 1,
): ADAttackPath {
  const path: ADAttackPath = {
    name,
    kind,
    source,
    target,
    technique_id: techniqueId,
    detail,
    requires_approval: true,
    hop_count: hopCount,
    toDict() {
      return {
        name: this.name,
        kind: this.kind,
        source: this.source.name,
        source_id: this.source.object_id,
        target: this.target.name,
        target_id: this.target.object_id,
        technique_id: this.technique_id,
        detail: this.detail,
        requires_approval: this.requires_approval,
        hop_count: this.hop_count,
      };
    },
  };
  return path;
}

export class AttackPathPlanner {
  graph: BloodHoundGraph;

  constructor(graph: BloodHoundGraph) {
    this.graph = graph;
  }

  kerberoastableUsers(): ADNode[] {
    return this.graph.users().filter((u) => u.hasSpn());
  }

  dcsyncCandidates(): ADNode[] {
    const candidates: ADNode[] = [];
    const seen = new Set<string>();
    for (const edge of this.graph.edges) {
      if (edge.label === "GetChangesAll" || edge.label === "GetChanges") {
        const node = this.graph.get(edge.source);
        if (node && !seen.has(node.object_id)) {
          seen.add(node.object_id);
          candidates.push(node);
        }
      }
    }
    return candidates;
  }

  aclAbuseEdges(): Array<[ADNode, ADNode, string, string]> {
    const results: Array<[ADNode, ADNode, string, string]> = [];
    for (const edge of this.graph.edges) {
      const mapped = ACL_ABUSE[edge.label];
      if (!mapped) continue;
      const source = this.graph.get(edge.source);
      const target = this.graph.get(edge.target);
      if (source && target) results.push([source, target, edge.label, mapped[0]]);
    }
    return results;
  }

  privilegeEscalationPaths(source: ADNode): ADAttackPath[] {
    const paths: ADAttackPath[] = [];
    const seenEdges = new Set<string>();
    const queue: Array<[ADNode, string[]]> = [[source, [source.object_id]]];
    let hops = 0;
    while (queue.length && hops < 4 && paths.length < 10) {
      const levelSize = queue.length;
      for (let i = 0; i < levelSize; i++) {
        const [current, trail] = queue.shift()!;
        for (const edge of this.graph.outgoing(current.object_id)) {
          const edgeKey = `${current.object_id}|${edge.target}`;
          if (seenEdges.has(edgeKey)) continue;
          seenEdges.add(edgeKey);
          const target = this.graph.get(edge.target);
          if (!target) continue;
          if (edge.label === "MemberOf" && isHighValue(target)) {
            paths.push(
              makeAttackPath(
                `${current.name} -> ${target.name} (MemberOf)`,
                "member-of",
                current,
                target,
                "T1078",
                `${current.name} is a member of high-privilege group ${target.name} via ${trail.length} hop(s).`,
                trail.length,
              ),
            );
          } else if (ACL_ABUSE[edge.label] && target.isComputer()) {
            const [technique, hint] = ACL_ABUSE[edge.label]!;
            paths.push(
              makeAttackPath(
                `${current.name} abuses ${edge.label} on ${target.name}`,
                "acl-abuse",
                current,
                target,
                technique,
                `${hint} — ${current.name} controls ${target.name}.`,
                trail.length,
              ),
            );
          }
          if (trail.length < 4) queue.push([target, [...trail, target.object_id]]);
        }
      }
      hops += 1;
    }
    return paths;
  }

  plan(controlled?: string): ADAttackPath[] {
    const paths: ADAttackPath[] = [];

    // 1. Kerberoasting — highest signal-to-noise credential attack.
    for (const user of this.kerberoastableUsers()) {
      paths.push(
        makeAttackPath(
          `Kerberoast ${user.name}`,
          "kerberoast",
          user,
          user,
          "T1558.003",
          `${user.name} has service principal names; request + crack a TGS.`,
        ),
      );
    }

    // 2. DCSync candidates.
    for (const node of this.dcsyncCandidates()) {
      paths.push(
        makeAttackPath(
          `DCSync via ${node.name}`,
          "dcsync",
          node,
          node,
          "T1003.006",
          `${node.name} holds GetChangesAll; replicate domain credentials.`,
        ),
      );
    }

    // 3. ACL abuse edges.
    for (const [source, target, label, technique] of this.aclAbuseEdges()) {
      const hint = ACL_ABUSE[label]![1];
      paths.push(
        makeAttackPath(
          `${source.name} ${label} ${target.name}`,
          "acl-abuse",
          source,
          target,
          technique,
          `${hint} — abuse ${label} to compromise ${target.name}.`,
        ),
      );
    }

    // 4. Privilege escalation toward high-value groups (bounded BFS).
    const roots = controlled ? [this.graph.findByName(controlled)].filter(Boolean) : this.controlledRoots();
    for (const root of roots) {
      if (root) paths.push(...this.privilegeEscalationPaths(root));
    }

    return paths;
  }

  private controlledRoots(): ADNode[] {
    const sources = new Set(
      this.graph.edges.filter((e) => ACL_ABUSE[e.label]).map((e) => e.source),
    );
    return [...sources]
      .map((s) => this.graph.get(s))
      .filter((n): n is ADNode => n !== undefined);
  }
}

function isHighValue(node: ADNode): boolean {
  const name = node.name.toLowerCase();
  return (
    PRIVILEGE_ORDER.some((p) => name.includes(p.toLowerCase())) ||
    Boolean(node.properties["highvalue"])
  );
}

export function attackPathToAction(path: ADAttackPath): Record<string, unknown> {
  return {
    action_id: `ad-${path.kind}-${path.source.name.length + path.target.name.length}`,
    kind: path.kind === "kerberoast" || path.kind === "dcsync" || path.kind === "acl-abuse" ? "exploit" : "post_exploit",
    title: path.name,
    description: path.detail,
    tool: "bloodhound",
    command: `ad-engine --${path.kind} --source ${path.source.name} --target ${path.target.name}`,
    requires_approval: path.requires_approval,
    technique_id: path.technique_id,
    status: "pending",
  };
}
