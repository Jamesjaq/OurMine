import { RGBA, TextAttributes } from "@opentui/core"
import type { TuiPlugin, TuiPluginApi } from "@opencode-ai/plugin/tui"
import { For } from "solid-js"
import { mineFiglet, ourFiglet } from "./logo-glyphs.ts"

const ACCENT = "#FF5733"

function OurMineLogo(props: { api: TuiPluginApi }) {
  const theme = () => props.api.theme.current
  const accent = () => RGBA.fromHex(ACCENT)

  return (
    <box flexDirection="row" gap={1} alignItems="flex-start">
      <box flexDirection="column">
        <For each={ourFiglet}>
          {(line) => (
            <text fg={theme().textMuted} attributes={TextAttributes.BOLD} selectable={false}>
              {line}
            </text>
          )}
        </For>
      </box>
      <box flexDirection="column">
        <For each={mineFiglet}>
          {(line) => (
            <text fg={accent()} attributes={TextAttributes.BOLD} selectable={false}>
              {line}
            </text>
          )}
        </For>
      </box>
    </box>
  )
}

const tui: TuiPlugin = async (api) => {
  api.slots.register({
    order: 1000,
    slots: {
      home_logo() {
        return <OurMineLogo api={api} />
      },
    },
  })
}

export default {
  id: "ourmine.brand",
  tui,
}
