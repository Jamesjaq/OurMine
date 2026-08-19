import { bootstrapOpenCode } from "./packages/security/src/opencode_bootstrap.ts";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

async function verify() {
  console.log("Running OurMine ARES Bootstrap...");
  const result = bootstrapOpenCode({ quiet: false });
  
  console.log("\nBootstrap Results:");
  console.log(`- Config Dir: ${result.configDir}`);
  console.log(`- Live Mode: ${result.live}`);
  console.log(`- Updated: ${result.updated}`);

  const config = JSON.parse(fs.readFileSync(result.configPath, "utf8"));
  console.log(`\nDefault Agent: ${config.default_agent}`);
  console.log(`ARES MCP Command: ${config.mcp.ares.command.join(" ")}`);
  
  const agentPath = result.agentPath;
  if (fs.existsSync(agentPath)) {
    const agentContent = fs.readFileSync(agentPath, "utf8");
    console.log(`\nAgent Metadata (Syndicate Prime):`);
    console.log(agentContent.split("---")[1]);
  }
}

verify().catch(console.error);
