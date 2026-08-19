import { moduleEnvelope } from "../module_helpers.ts";
export async function runLiveVector(req: any, opts: any = {}) { return moduleEnvelope(opts.live !== false, { ok: true }); }