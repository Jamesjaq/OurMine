import { ToolBroker } from "../tool_broker.ts"
import { OpsecThrottleEngine } from "../opsec_throttle.ts"
import { resolveLiveMode } from "../exec_options.ts"

export function mcpLive(): boolean {
  return resolveLiveMode()
}

export const mcpContext = {
  get mcpLive() {
    return mcpLive
  },
  toolBroker: new ToolBroker(),
  globalThrottleEngine: new OpsecThrottleEngine(),
}

export default mcpContext
