import * as fs from "node:fs"
import * as security from "../../index.ts"
import * as dispatch from "../../mcp_dispatch.ts"
import { PentestAgent } from "../../pentestgpt_agent.ts"
import { ContextGuard } from "../../context_guard.ts"
import { gateExecution } from "../../opsec_gate.ts"
import type { McpTool } from "../../mcp_tool_types.ts"
import { buildActionablePlan } from "../../pentest_plan_builder.ts"
import { runEngagementSlice } from "../../engagement_slice.ts"
import { runEngagementAutopilot } from "../../engagement_autopilot.ts"
import { readArtifact } from "../../mcp_artifacts.ts"
import { mcpContext } from "../context.ts"

export function buildOtTools(): McpTool[] {
  const { mcpLive, toolBroker, globalThrottleEngine } = mcpContext
  return [
    {
        name: "ares_iot_scada",
        description: "IoT/SCADA exploitation: Modbus register read/write, DNP3 spoofing, MQTT broker abuse, BACnet enumeration, industrial protocol fuzzing.",
        inputSchema: {
          type: "object",
          properties: {
            host:     { type: "string", description: "Target host or IP" },
            protocol: { type: "string", description: "Industrial protocol", enum: ["modbus","dnp3","mqtt","bacnet","profinet","coap","s7"] },
            action:   { type: "string", description: "Action", enum: ["enumerate","read","write","fuzz","exploit"] },
          },
          required: ["host", "protocol"],
        },
        async handler({ host, protocol, action }) {
          const live = mcpLive()
          return dispatch.iotScadaExecute({ host: String(host), protocol: String(protocol), action: String(action ?? "enumerate") }, { live })
        },
      },

    {
        name: "ares_firmware",
        description: "Firmware analysis: binwalk-style extraction, entropy analysis, UART pinout detection, hardcoded credential search, binary patching.",
        inputSchema: {
          type: "object",
          properties: {
            path:   { type: "string", description: "Firmware file path" },
            action: { type: "string", description: "Analysis action", enum: ["extract","entropy","strings","credentials","patch","uart_detect"] },
          },
          required: ["path", "action"],
        },
        async handler({ path, action }) {
          const live = mcpLive()
          return dispatch.firmwareAnalyze({ path: String(path), action: String(action) }, { live })
        },
      }
  ]
}
