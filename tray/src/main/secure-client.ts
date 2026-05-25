import { SecureClient, type VerificationDocument } from 'tinfoil'

import { REVERIFY_INTERVAL_MS } from './constants.js'
import { fetchRouters } from './routers.js'
import { stateStore, type RouterState, type VerificationStatus } from './state.js'

interface ClientEntry {
  router: string
  client: SecureClient
  status: VerificationStatus
  document?: VerificationDocument
  lastError?: string
}

const clients = new Map<string, ClientEntry>()
let reverifyTimer: NodeJS.Timeout | undefined
let reverifyInFlight = false
let roundRobinCursor = 0

function describeError(err: unknown): string {
  if (err instanceof Error) return err.message
  try {
    return JSON.stringify(err)
  } catch {
    return String(err)
  }
}

function snapshotRouters(): RouterState[] {
  return Array.from(clients.values()).map((entry) => ({
    router: entry.router,
    status: entry.status,
    lastError: entry.lastError,
    document: entry.document
  }))
}

function updateGlobalStatus(): void {
  const entries = Array.from(clients.values())
  if (entries.length === 0) {
    stateStore.set({
      status: 'initializing',
      statusMessage: 'Waiting for routers…',
      routers: snapshotRouters()
    })
    return
  }
  const verified = entries.filter((e) => e.status === 'verified')
  const failed = entries.filter((e) => e.status === 'failed')
  let status: VerificationStatus = 'initializing'
  let statusMessage = 'Verifying enclave attestation…'
  let lastError: string | undefined
  if (verified.length === entries.length) {
    status = 'verified'
    statusMessage =
      entries.length === 1
        ? 'Connection secure and attestation verified'
        : `All ${entries.length} routers verified`
  } else if (failed.length > 0 && verified.length === 0) {
    status = 'failed'
    statusMessage = 'Attestation failed'
    lastError = failed[0]?.lastError
  } else if (verified.length > 0 && failed.length > 0) {
    status = 'verified'
    statusMessage = `${verified.length} of ${entries.length} routers verified`
    lastError = failed[0]?.lastError
  }
  stateStore.set({
    status,
    statusMessage,
    routers: snapshotRouters(),
    lastError
  })
}

function applyEntryFromDoc(entry: ClientEntry, doc: VerificationDocument): void {
  entry.document = doc
  if (doc.securityVerified) {
    entry.status = 'verified'
    entry.lastError = undefined
  } else {
    const failedStep = Object.entries(doc.steps).find(([, step]) => step?.status === 'failed')
    entry.status = 'failed'
    entry.lastError = failedStep?.[1]?.error ?? 'Attestation incomplete'
  }
  updateGlobalStatus()
}

export async function activateRouters(routers: string[]): Promise<void> {
  for (const host of Array.from(clients.keys())) {
    if (!routers.includes(host)) {
      clients.delete(host)
    }
  }

  for (const router of routers) {
    if (!clients.has(router)) {
      const entry: ClientEntry = {
        router,
        client: new SecureClient({
          enclaveURL: `https://${router}`,
          transport: 'tls'
        }),
        status: 'initializing'
      }
      clients.set(router, entry)
    }
  }

  updateGlobalStatus()

  await Promise.all(
    routers.map(async (router) => {
      const entry = clients.get(router)
      if (!entry) return
      entry.status = 'initializing'
      entry.lastError = undefined
      try {
        await entry.client.ready()
        applyEntryFromDoc(entry, entry.client.getVerificationDocument())
      } catch (err) {
        entry.status = 'failed'
        entry.lastError = describeError(err)
        updateGlobalStatus()
      }
    })
  )

  scheduleReverify()
}

function scheduleReverify(): void {
  if (reverifyTimer) return
  reverifyTimer = setInterval(() => {
    if (reverifyInFlight) return
    reverifyInFlight = true
    reverifyAll().finally(() => {
      reverifyInFlight = false
    })
  }, REVERIFY_INTERVAL_MS)
}

async function reverifyAll(): Promise<void> {
  await Promise.all(
    Array.from(clients.values()).map(async (entry) => {
      try {
        entry.client.reset()
        await entry.client.ready()
        applyEntryFromDoc(entry, entry.client.getVerificationDocument())
      } catch (err) {
        entry.status = 'failed'
        entry.lastError = describeError(err)
        updateGlobalStatus()
      }
    })
  )
}

export function getClient(router: string): SecureClient | undefined {
  return clients.get(router)?.client
}

export function getEntry(router: string): { status: VerificationStatus; document?: VerificationDocument } | undefined {
  const e = clients.get(router)
  return e ? { status: e.status, document: e.document } : undefined
}

export function knownRouters(): string[] {
  return Array.from(clients.keys())
}

export function verifiedRouters(): string[] {
  return Array.from(clients.values())
    .filter((e) => e.status === 'verified')
    .map((e) => e.router)
}

export function pickRoundRobinRouter(): string | undefined {
  const verified = verifiedRouters()
  if (verified.length === 0) {
    const any = knownRouters()
    return any[roundRobinCursor++ % Math.max(any.length, 1)]
  }
  const pick = verified[roundRobinCursor++ % verified.length]
  return pick
}

export function disposeSecureClients(): void {
  if (reverifyTimer) {
    clearInterval(reverifyTimer)
    reverifyTimer = undefined
  }
  clients.clear()
}

export async function refreshRouters(): Promise<void> {
  try {
    const routers = await fetchRouters()
    stateStore.set({ lastError: undefined })
    await activateRouters(routers)
  } catch (err) {
    stateStore.set({ lastError: `Could not fetch routers: ${describeError(err)}` })
  }
}
