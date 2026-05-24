import { EventEmitter } from 'node:events'
import type { VerificationDocument } from 'tinfoil'

export type VerificationStatus = 'initializing' | 'verified' | 'failed'

export interface RouterState {
  router: string
  status: VerificationStatus
  lastError?: string
  document?: VerificationDocument
}

export interface SystemProxyState {
  enabled: boolean
  trusted: boolean
  pacUrl?: string
  caCertPath?: string
  message?: string
}

export interface TrayState {
  status: VerificationStatus
  statusMessage: string
  port: number
  endpoint?: string
  routers: RouterState[]
  systemProxy: SystemProxyState
  lastError?: string
}

type Listener = (state: TrayState) => void

class StateStore extends EventEmitter {
  private state: TrayState

  constructor(initial: TrayState) {
    super()
    this.state = initial
  }

  get(): TrayState {
    return this.state
  }

  set(partial: Partial<TrayState>): void {
    this.state = { ...this.state, ...partial }
    this.emit('change', this.state)
  }

  onChange(listener: Listener): () => void {
    this.on('change', listener)
    return () => this.off('change', listener)
  }
}

export const stateStore = new StateStore({
  status: 'initializing',
  statusMessage: 'Starting…',
  port: 0,
  routers: [],
  systemProxy: { enabled: false, trusted: false }
})
