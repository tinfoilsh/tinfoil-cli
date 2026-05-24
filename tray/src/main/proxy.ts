import { spawn, type ChildProcessByStdio } from 'node:child_process'
import type { Readable } from 'node:stream'
import { existsSync } from 'node:fs'
import { join } from 'node:path'
import { app } from 'electron'

import { PROXY_LISTEN_HOST } from './constants.js'
import { stateStore } from './state.js'

const PROXY_STOP_GRACE_MS = 3000

type CliProcess = ChildProcessByStdio<null, Readable, Readable>

let child: CliProcess | undefined
let intentionalShutdown = false
let stopWaiter: Promise<void> | undefined

function binaryFileName(): string {
  return process.platform === 'win32' ? 'tinfoil.exe' : 'tinfoil'
}

function locateBinary(): string {
  const name = binaryFileName()
  const candidates: string[] = []
  if (app.isPackaged) {
    candidates.push(join(process.resourcesPath, 'bin', name))
  } else {
    candidates.push(join(app.getAppPath(), 'resources', 'bin', name))
    candidates.push(join(app.getAppPath(), '..', name))
  }
  for (const candidate of candidates) {
    if (existsSync(candidate)) return candidate
  }
  return candidates[0] ?? name
}

export function proxyEndpoint(port: number): string {
  return `http://${PROXY_LISTEN_HOST}:${port}/v1`
}

function setProxyState(partial: Partial<ReturnType<typeof stateStore.get>['proxy']>): void {
  const current = stateStore.get().proxy
  stateStore.set({ proxy: { ...current, ...partial } })
}

function attachLogging(proc: CliProcess): void {
  proc.stdout.setEncoding('utf8')
  proc.stderr.setEncoding('utf8')
  proc.stdout.on('data', (chunk: string) => {
    for (const line of chunk.split('\n')) {
      if (line.trim().length > 0) console.log('[tinfoil]', line)
    }
  })
  proc.stderr.on('data', (chunk: string) => {
    for (const line of chunk.split('\n')) {
      if (line.trim().length > 0) console.warn('[tinfoil]', line)
    }
  })
}

async function waitForExit(proc: CliProcess): Promise<void> {
  return new Promise<void>((resolve) => {
    if (proc.exitCode !== null) {
      resolve()
      return
    }
    proc.once('exit', () => resolve())
  })
}

export async function startProxy(port: number): Promise<{ port: number; endpoint: string } | null> {
  if (child) {
    await stopProxy()
  }

  const binary = locateBinary()
  if (!existsSync(binary)) {
    const message = `Tinfoil CLI not found at ${binary}`
    setProxyState({ enabled: true, running: false, port, lastError: message })
    return null
  }

  intentionalShutdown = false
  const args = ['proxy', '-p', String(port), '-b', PROXY_LISTEN_HOST]
  const proc = spawn(binary, args, {
    stdio: ['ignore', 'pipe', 'pipe'],
    env: { ...process.env }
  })
  attachLogging(proc)

  proc.on('exit', (code, signal) => {
    const wasIntentional = intentionalShutdown
    child = undefined
    if (wasIntentional) {
      setProxyState({ running: false, lastError: undefined })
    } else {
      const message = `Tinfoil proxy exited unexpectedly (${signal ?? `code ${code ?? 0}`})`
      setProxyState({ running: false, lastError: message })
    }
  })

  proc.on('error', (err) => {
    child = undefined
    setProxyState({ running: false, lastError: err.message })
  })

  child = proc
  setProxyState({ enabled: true, running: true, port, lastError: undefined })
  return { port, endpoint: proxyEndpoint(port) }
}

export async function stopProxy(): Promise<void> {
  const proc = child
  if (!proc) return
  if (stopWaiter) return stopWaiter
  intentionalShutdown = true
  stopWaiter = (async () => {
    try {
      proc.kill('SIGTERM')
      const settled = await Promise.race([
        waitForExit(proc),
        new Promise<'timeout'>((resolve) => setTimeout(() => resolve('timeout'), PROXY_STOP_GRACE_MS))
      ])
      if (settled === 'timeout' && proc.exitCode === null) {
        proc.kill('SIGKILL')
        await waitForExit(proc)
      }
    } finally {
      stopWaiter = undefined
    }
  })()
  return stopWaiter
}

export function isProxyRunning(): boolean {
  return child !== undefined && child.exitCode === null
}
