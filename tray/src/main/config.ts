import { promises as fs } from 'node:fs'
import { join } from 'node:path'
import { app } from 'electron'

import { PROXY_DEFAULT_PORT } from './constants.js'

export interface PersistedConfig {
  port: number
  proxyEnabled: boolean
  launchAtLogin: boolean
}

const FILE_NAME = 'config.json'
const MIN_PORT = 1
const MAX_PORT = 65535

function configPath(): string {
  return join(app.getPath('userData'), FILE_NAME)
}

function isValidPort(value: unknown): value is number {
  return (
    typeof value === 'number' &&
    Number.isInteger(value) &&
    value >= MIN_PORT &&
    value <= MAX_PORT
  )
}

export async function loadConfig(): Promise<PersistedConfig> {
  try {
    const raw = await fs.readFile(configPath(), 'utf8')
    const parsed = JSON.parse(raw) as Partial<PersistedConfig> & { systemProxyEnabled?: boolean }
    const port = isValidPort(parsed.port) ? parsed.port : PROXY_DEFAULT_PORT
    const proxyEnabled =
      typeof parsed.proxyEnabled === 'boolean' ? parsed.proxyEnabled : !!parsed.systemProxyEnabled
    const launchAtLogin = typeof parsed.launchAtLogin === 'boolean' ? parsed.launchAtLogin : true
    return { port, proxyEnabled, launchAtLogin }
  } catch {
    return { port: PROXY_DEFAULT_PORT, proxyEnabled: true, launchAtLogin: true }
  }
}

export async function saveConfig(cfg: PersistedConfig): Promise<void> {
  const path = configPath()
  await fs.mkdir(join(path, '..'), { recursive: true })
  await fs.writeFile(path, JSON.stringify(cfg, null, 2), 'utf8')
}
