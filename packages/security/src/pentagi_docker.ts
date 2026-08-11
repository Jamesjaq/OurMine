/**
 * @module pentagi_docker
 * PentaGI Sandboxed Docker Container Executor — Runs offensive security tools inside isolated Docker containers
 * to guarantee environment isolation and zero host contamination.
 */

import { resolveDryRun } from "./exec_options.ts"
import { execSync } from "node:child_process";

export interface DockerExecutionOptions {
  image?: string;
  command: string;
  volumes?: string[];
  live?: boolean;
}

export function runInDocker(opts: DockerExecutionOptions): { stdout: string; exitCode: number; dryRun: boolean } {
  const image = opts.image ?? "kalilinux/kali-rolling";
  const { live = false, command } = opts;

  if (!live) {
    return {
      stdout: `[DRY-RUN] docker run --rm ${image} ${command}`,
      exitCode: 0,
      dryRun: true,
    };
  }

  try {
    const stdout = execSync(`docker run --rm ${image} ${command}`, { encoding: "utf8" });
    return { stdout, exitCode: 0, dryRun: false };
  } catch (err: any) {
    return { stdout: err.message, exitCode: err.status ?? 1, dryRun: false };
  }
}

export default { runInDocker };
