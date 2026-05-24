import { promises as fs } from 'node:fs'
import { join } from 'node:path'
import { app } from 'electron'

import { PROXY_DEFAULT_PORT } from './constants.js'

export interface PersistedConfig {
  port: number
  proxyEnabled: boolean
}

const FILE_NAME = 'config.json'

function configPath(): string {
  return join(app.getPath('userData'), FILE_NAME)
}

export async function loadConfig(): Promise<PersistedConfig> {
  try {
    const raw = await fs.readFile(configPath(), 'utf8')
    const parsed = JSON.parse(raw) as Partial<PersistedConfig> & { systemProxyEnabled?: boolean }
    const port = typeof parsed.port === 'number' && parsed.port > 0 ? parsed.port : PROXY_DEFAULT_PORT
    const proxyEnabled =
      typeof parsed.proxyEnabled === 'boolean' ? parsed.proxyEnabled : !!parsed.systemProxyEnabled
    return { port, proxyEnabled }
  } catch {
    return { port: PROXY_DEFAULT_PORT, proxyEnabled: true }
  }
}

export async function saveConfig(cfg: PersistedConfig): Promise<void> {
  const path = configPath()
  await fs.mkdir(join(path, '..'), { recursive: true })
  await fs.writeFile(path, JSON.stringify(cfg, null, 2), 'utf8')
}
