/**
 * LLM Client Wrapper
 *
 * Wraps OpenCode's LLM provider infrastructure for security module use.
 * Supports Anthropic, OpenAI, Google via OpenCode's existing provider system.
 *
 * Reads API keys from:
 *   - Environment variables (ANTHROPIC_API_KEY, OPENAI_API_KEY, GOOGLE_API_KEY)
 *   - ~/.config/opencode/auth.json
 *   - ~/.config/opencode/config.json
 */

import * as fs from "node:fs"
import * as path from "node:path"
import * as os from "node:os"

export interface LLMMessage {
  role: "system" | "user" | "assistant"
  content: string
}

export interface LLMOptions {
  provider?: "anthropic" | "openai" | "google" | "auto"
  model?: string
  maxTokens?: number
  temperature?: number
  system?: string
}

export interface LLMResponse {
  content: string
  provider: string
  model: string
  usage: { input: number; output: number }
}

interface ProviderConfig {
  apiKey: string
  baseUrl: string
  defaultModel: string
}

const PROVIDER_CONFIGS: Record<string, (apiKey: string) => ProviderConfig> = {
  anthropic: (key) => ({
    apiKey: key,
    baseUrl: "https://api.anthropic.com/v1",
    defaultModel: "claude-sonnet-4-20250514",
  }),
  openai: (key) => ({
    apiKey: key,
    baseUrl: process.env.OPENAI_API_BASE || "https://api.openai.com/v1",
    defaultModel: process.env.OPENAI_MODEL || "gpt-5-nano",
  }),
  google: (key) => ({
    apiKey: key,
    baseUrl: "https://generativelanguage.googleapis.com/v1beta",
    defaultModel: "gemini-2.0-flash",
  }),
}

function loadAuthFromConfig(): Record<string, string> {
  const keys: Record<string, string> = {}

  const envMap: Record<string, string> = {
    ANTHROPIC_API_KEY: "anthropic",
    OPENAI_API_KEY: "openai",
    GOOGLE_API_KEY: "google",
    GEMINI_API_KEY: "google",
  }

  for (const [env, provider] of Object.entries(envMap)) {
    if (process.env[env]) keys[provider] = process.env[env]!
  }

  try {
    const authPath = path.join(os.homedir(), ".config", "opencode", "auth.json")
    if (fs.existsSync(authPath)) {
      const auth = JSON.parse(fs.readFileSync(authPath, "utf-8"))
      if (auth.anthropic?.type === "api" && auth.anthropic.key) keys.anthropic = auth.anthropic.key
      if (auth.openai?.type === "api" && auth.openai.key) keys.openai = auth.openai.key
      if (auth.google?.type === "api" && auth.google.key) keys.google = auth.google.key
    }
  } catch {}

  try {
    const configPath = path.join(os.homedir(), ".config", "opencode", "config.json")
    if (fs.existsSync(configPath)) {
      const config = JSON.parse(fs.readFileSync(configPath, "utf-8"))
      if (config.provider?.anthropic?.options?.apiKey) keys.anthropic = config.provider.anthropic.options.apiKey
      if (config.provider?.openai?.options?.apiKey) keys.openai = config.provider.openai.options.apiKey
      if (config.provider?.google?.options?.apiKey) keys.google = config.provider.google.options.apiKey
    }
  } catch {}

  return keys
}

function detectProviderAndKey(preferred?: string): { provider: string; config: ProviderConfig } {
  const keys = loadAuthFromConfig()

  if (preferred && preferred !== "auto" && keys[preferred]) {
    return { provider: preferred, config: PROVIDER_CONFIGS[preferred](keys[preferred]) }
  }

  if (keys.anthropic) return { provider: "anthropic", config: PROVIDER_CONFIGS.anthropic(keys.anthropic) }
  if (keys.openai) return { provider: "openai", config: PROVIDER_CONFIGS.openai(keys.openai) }
  if (keys.google) return { provider: "google", config: PROVIDER_CONFIGS.google(keys.google) }

  throw new Error(
    "No LLM API key found. Set one of:\n" +
    "  - ANTHROPIC_API_KEY env var\n" +
    "  - OPENAI_API_KEY env var\n" +
    "  - GOOGLE_API_KEY env var\n" +
    "  - ~/.config/opencode/auth.json\n" +
    "  - ~/.config/opencode/config.json"
  )
}

async function callAnthropic(config: ProviderConfig, messages: LLMMessage[], options: LLMOptions): Promise<LLMResponse> {
  const model = options.model || config.defaultModel
  const systemMsg = messages.find(m => m.role === "system")
  const nonSystem = messages.filter(m => m.role !== "system")

  const body: Record<string, unknown> = {
    model,
    max_tokens: options.maxTokens || 4096,
    messages: nonSystem.map(m => ({ role: m.role, content: m.content })),
  }
  if (systemMsg) body.system = systemMsg.content
  if (options.temperature !== undefined) body.temperature = options.temperature

  const res = await fetch(`${config.baseUrl}/messages`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "x-api-key": config.apiKey,
      "anthropic-version": "2023-06-01",
    },
    body: JSON.stringify(body),
  })

  if (!res.ok) {
    const err = await res.text()
    throw new Error(`Anthropic API error ${res.status}: ${err}`)
  }

  const data = await res.json() as { content: { type: string; text: string }[]; usage: { input_tokens: number; output_tokens: number } }
  return {
    content: data.content.map(c => c.text).join(""),
    provider: "anthropic",
    model,
    usage: { input: data.usage.input_tokens, output: data.usage.output_tokens },
  }
}

async function callOpenAI(config: ProviderConfig, messages: LLMMessage[], options: LLMOptions): Promise<LLMResponse> {
  const model = options.model || config.defaultModel

  const body: Record<string, unknown> = {
    model,
    messages: messages.map(m => ({ role: m.role, content: m.content })),
    max_tokens: options.maxTokens || 4096,
  }
  if (options.temperature !== undefined) body.temperature = options.temperature

  const res = await fetch(`${config.baseUrl}/chat/completions`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${config.apiKey}`,
    },
    body: JSON.stringify(body),
  })

  if (!res.ok) {
    const err = await res.text()
    throw new Error(`OpenAI API error ${res.status}: ${err}`)
  }

  const data = await res.json() as { choices: { message: { content: string } }[]; usage: { prompt_tokens: number; completion_tokens: number } }
  return {
    content: data.choices[0]?.message?.content || "",
    provider: "openai",
    model,
    usage: { input: data.usage.prompt_tokens, output: data.usage.completion_tokens },
  }
}

async function callGoogle(config: ProviderConfig, messages: LLMMessage[], options: LLMOptions): Promise<LLMResponse> {
  const model = options.model || config.defaultModel
  const systemMsg = messages.find(m => m.role === "system")
  const nonSystem = messages.filter(m => m.role !== "system")

  const contents = nonSystem.map(m => ({
    role: m.role === "assistant" ? "model" : "user",
    parts: [{ text: m.content }],
  }))

  const body: Record<string, unknown> = {
    contents,
    generationConfig: {
      maxOutputTokens: options.maxTokens || 4096,
      temperature: options.temperature,
    },
  }
  if (systemMsg) {
    body.systemInstruction = { parts: [{ text: systemMsg.content }] }
  }

  const res = await fetch(`${config.baseUrl}/models/${model}:generateContent?key=${config.apiKey}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  })

  if (!res.ok) {
    const err = await res.text()
    throw new Error(`Google API error ${res.status}: ${err}`)
  }

  const data = await res.json() as { candidates: { content: { parts: { text: string }[] } }[]; usageMetadata: { promptTokenCount: number; candidatesTokenCount: number } }
  return {
    content: data.candidates?.[0]?.content?.parts?.[0]?.text || "",
    provider: "google",
    model,
    usage: { input: data.usageMetadata?.promptTokenCount || 0, output: data.usageMetadata?.candidatesTokenCount || 0 },
  }
}

export async function llmComplete(prompt: string, options: LLMOptions = {}): Promise<LLMResponse> {
  const { provider, config } = detectProviderAndKey(options.provider)
  const messages: LLMMessage[] = []
  if (options.system) messages.push({ role: "system", content: options.system })
  messages.push({ role: "user", content: prompt })

  switch (provider) {
    case "anthropic": return callAnthropic(config, messages, options)
    case "openai": return callOpenAI(config, messages, options)
    case "google": return callGoogle(config, messages, options)
    default: throw new Error(`Unsupported provider: ${provider}`)
  }
}

export async function llmChat(messages: LLMMessage[], options: LLMOptions = {}): Promise<LLMResponse> {
  const { provider, config } = detectProviderAndKey(options.provider)
  switch (provider) {
    case "anthropic": return callAnthropic(config, messages, options)
    case "openai": return callOpenAI(config, messages, options)
    case "google": return callGoogle(config, messages, options)
    default: throw new Error(`Unsupported provider: ${provider}`)
  }
}

export async function llmClassify(text: string, categories: string[], options: LLMOptions = {}): Promise<{ category: string; confidence: number; reasoning: string }> {
  const system = `You are a classification engine. Classify the input into exactly one of these categories: ${categories.join(", ")}. Respond with JSON: {"category": "...", "confidence": 0.0-1.0, "reasoning": "..."}`
  const response = await llmComplete(text, { ...options, system })
  try {
    const parsed = JSON.parse(response.content)
    return { category: parsed.category || categories[0], confidence: parsed.confidence || 0.5, reasoning: parsed.reasoning || "" }
  } catch {
    return { category: categories[0], confidence: 0.3, reasoning: "Failed to parse LLM response" }
  }
}

export async function llmExtract(text: string, schema: Record<string, string>, options: LLMOptions = {}): Promise<Record<string, unknown>> {
  const schemaDesc = Object.entries(schema).map(([k, v]) => `- ${k} (${v})`).join("\n")
  const system = `Extract structured data from the input. Return JSON matching this schema:\n${schemaDesc}`
  const response = await llmComplete(text, { ...options, system })
  try {
    return JSON.parse(response.content)
  } catch {
    return {}
  }
}

export function hasLLMKey(): boolean {
  try {
    detectProviderAndKey()
    return true
  } catch {
    return false
  }
}

export function listProviders(): string[] {
  const keys = loadAuthFromConfig()
  return Object.keys(keys).filter(k => keys[k])
}
