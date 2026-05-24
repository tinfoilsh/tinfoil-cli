import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

const VERIFICATION_CENTER_BASE_URL = 'https://verification-center.tinfoil.sh'
const VERIFICATION_CENTER_ORIGIN = new URL(VERIFICATION_CENTER_BASE_URL).origin
const SEND_RETRY_DELAYS_MS = [100, 300, 800, 2000]
const REFRESH_MIN_SPIN_MS = 1000

type TrayState = Awaited<ReturnType<typeof window.tinfoil.getState>>
type Router = TrayState['routers'][number]

function useDarkMode(): boolean {
  const [dark, setDark] = useState(() =>
    window.matchMedia('(prefers-color-scheme: dark)').matches
  )
  useEffect(() => {
    const mql = window.matchMedia('(prefers-color-scheme: dark)')
    const onChange = (event: MediaQueryListEvent) => setDark(event.matches)
    mql.addEventListener('change', onChange)
    return () => mql.removeEventListener('change', onChange)
  }, [])
  return dark
}

function dotForRouter(r: Router): string {
  switch (r.status) {
    case 'verified':
      return 'router-dot router-verified'
    case 'failed':
      return 'router-dot router-failed'
    default:
      return 'router-dot'
  }
}

type LockState = 'verified' | 'failed' | 'off' | 'initializing'

function LockBadge({ state }: { state: LockState }) {
  const closed = state === 'verified'
  return (
    <span className={`lock lock-${state}`} aria-hidden="true">
      <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
        {closed ? (
          <path d="M8 10V7a4 4 0 0 1 8 0v3" />
        ) : (
          <path d="M8 10V7a4 4 0 0 1 7.46-2" />
        )}
        <rect x="5" y="10" width="14" height="10" rx="2.2" />
        <circle cx="12" cy="15" r="1.4" fill="currentColor" stroke="none" />
      </svg>
    </span>
  )
}

function postToIframe(iframe: HTMLIFrameElement | null, message: unknown): void {
  iframe?.contentWindow?.postMessage(message, VERIFICATION_CENTER_ORIGIN)
}

export default function App() {
  const [state, setState] = useState<TrayState | null>(null)
  const [iframeReady, setIframeReady] = useState(false)
  const [busy, setBusy] = useState(false)
  const [selectedRouter, setSelectedRouter] = useState<string | null>(null)
  const [portInput, setPortInput] = useState<string>('')
  const iframeRef = useRef<HTMLIFrameElement | null>(null)
  const cardRef = useRef<HTMLDivElement | null>(null)
  const isDark = useDarkMode()

  useEffect(() => {
    const node = cardRef.current
    if (!node) return
    const report = () => {
      void window.tinfoil.setCompactHeight(Math.ceil(node.getBoundingClientRect().height))
    }
    report()
    const ro = new ResizeObserver(() => report())
    ro.observe(node)
    return () => ro.disconnect()
  }, [state])

  useEffect(() => {
    void window.tinfoil.getState().then(setState)
    return window.tinfoil.onStateChanged(setState)
  }, [])

  useEffect(() => {
    if (!state) return
    setPortInput((prev) => (prev === '' ? String(state.proxy.port) : prev))
  }, [state])

  const selectedDocument = useMemo(() => {
    if (!selectedRouter || !state) return null
    return state.routers.find((r) => r.router === selectedRouter)?.document ?? null
  }, [selectedRouter, state])

  useEffect(() => {
    if (!iframeReady || !selectedDocument) return
    const iframe = iframeRef.current
    const send = () =>
      postToIframe(iframe, {
        type: 'TINFOIL_VERIFICATION_DOCUMENT',
        document: selectedDocument
      })
    send()
    const timers = SEND_RETRY_DELAYS_MS.map((delay) => setTimeout(send, delay))
    return () => timers.forEach(clearTimeout)
  }, [iframeReady, selectedDocument])

  useEffect(() => {
    const handle = (event: MessageEvent) => {
      if (event.origin !== VERIFICATION_CENTER_ORIGIN) return
      const type = (event.data as { type?: string } | undefined)?.type
      if (type === 'TINFOIL_VERIFICATION_CENTER_READY') {
        setIframeReady(true)
      } else if (type === 'TINFOIL_REQUEST_VERIFICATION_DOCUMENT' && selectedDocument) {
        postToIframe(iframeRef.current, {
          type: 'TINFOIL_VERIFICATION_DOCUMENT',
          document: selectedDocument
        })
      } else if (type === 'TINFOIL_VERIFICATION_CENTER_CLOSED') {
        setSelectedRouter(null)
      }
    }
    window.addEventListener('message', handle)
    return () => window.removeEventListener('message', handle)
  }, [selectedDocument])

  const isExpanded = selectedRouter !== null

  useEffect(() => {
    if (!iframeReady) return
    postToIframe(iframeRef.current, {
      type: isExpanded ? 'TINFOIL_VERIFICATION_CENTER_OPEN' : 'TINFOIL_VERIFICATION_CENTER_CLOSE'
    })
  }, [iframeReady, isExpanded])

  useEffect(() => {
    void window.tinfoil.setExpanded(isExpanded)
  }, [isExpanded])

  const iframeUrl = useMemo(() => {
    const params = new URLSearchParams({
      darkMode: String(isDark),
      showVerificationFlow: 'true',
      compact: 'false',
      open: 'true'
    })
    return `${VERIFICATION_CENTER_BASE_URL}?${params.toString()}`
  }, [isDark])

  const onToggleActive = useCallback(async () => {
    if (!state) return
    setBusy(true)
    try {
      const next = !state.proxy.enabled
      const updated = await window.tinfoil.setProxyEnabled(next)
      setState(updated)
      if (!next) setSelectedRouter(null)
    } finally {
      setBusy(false)
    }
  }, [state])

  const onSelectRouter = useCallback((router: string) => {
    setSelectedRouter((prev) => (prev === router ? null : router))
  }, [])

  const onCommitPort = useCallback(async () => {
    if (!state) return
    const next = Number(portInput)
    if (!Number.isFinite(next) || !Number.isInteger(next) || next < 1 || next > 65535) {
      setPortInput(String(state.proxy.port))
      return
    }
    if (next === state.proxy.port) return
    const updated = await window.tinfoil.setProxyPort(next)
    setState(updated)
  }, [portInput, state])

  const onToggleLaunchAtLogin = useCallback(async () => {
    if (!state) return
    const updated = await window.tinfoil.setLaunchAtLogin(!state.launchAtLogin)
    setState(updated)
  }, [state])

  const [copied, setCopied] = useState(false)
  const onCopyEndpoint = useCallback(async () => {
    const value = await window.tinfoil.copyEndpoint()
    if (!value) return
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }, [])

  const [refreshing, setRefreshing] = useState(false)
  const onRefreshRouters = useCallback(async () => {
    if (refreshing) return
    setRefreshing(true)
    const minDuration = new Promise((resolve) => setTimeout(resolve, REFRESH_MIN_SPIN_MS))
    try {
      const [updated] = await Promise.all([window.tinfoil.refreshRouters(), minDuration])
      setState(updated)
    } finally {
      setRefreshing(false)
    }
  }, [refreshing])

  if (!state) {
    return (
      <div className={`shell compact ${isDark ? 'dark' : 'light'}`}>
        <div className="card">
          <div className="status-row">
            <LockBadge state="initializing" />
            <span className="status-text">Loading…</span>
          </div>
        </div>
      </div>
    )
  }

  const enabled = state.proxy.enabled
  const running = state.proxy.running
  const active = enabled && running

  const statusTitle = enabled
    ? !running
      ? state.proxy.lastError
        ? "Couldn't start the proxy"
        : 'Starting Tinfoil proxy…'
      : state.status === 'failed'
        ? "We couldn't confirm your connection is private"
        : state.status === 'initializing'
          ? 'Verifying Tinfoil enclaves…'
          : "You're protected by Tinfoil"
    : 'Tinfoil is off'

  const statusSub = enabled
    ? !running
      ? state.proxy.lastError ?? 'The Tinfoil CLI is starting on the configured port.'
      : state.routers.length > 0
        ? 'Every API request is routed through an attested enclave whose code and hardware are verified end-to-end.'
        : 'Verifying enclave attestations…'
    : 'Turn this on to start the local Tinfoil proxy and route API requests through attested enclaves.'

  return (
    <div className={`shell ${isExpanded ? 'expanded' : 'compact'} ${active ? 'active' : 'inactive'} ${isDark ? 'dark' : 'light'}`}>
      <div className="card" ref={cardRef}>
        <div className="status-row">
          <LockBadge
            state={
              !active
                ? 'off'
                : state.status === 'failed'
                  ? 'failed'
                  : state.status === 'initializing'
                    ? 'initializing'
                    : 'verified'
            }
          />
          <div className="status-text">
            <div className="status-title">{statusTitle}</div>
            <div className="status-sub">{statusSub}</div>
          </div>
          <button
            type="button"
            className={`toggle ${enabled ? 'on' : 'off'}`}
            onClick={onToggleActive}
            disabled={busy}
            aria-pressed={enabled}
            title={enabled ? 'Stop proxy' : 'Start proxy'}
          >
            <span className="knob" />
          </button>
        </div>

        <div className="port-row">
          <label className="port-label" htmlFor="proxy-port">
            Port
          </label>
          <input
            id="proxy-port"
            className="port-input"
            type="number"
            min={1}
            max={65535}
            value={portInput}
            onChange={(e) => setPortInput(e.target.value)}
            onBlur={() => {
              void onCommitPort()
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter') {
                e.currentTarget.blur()
              }
            }}
          />
          {state.launchAtLoginSupported && (
            <label className="launch-row" title="Start Tinfoil when you log in">
              <input
                type="checkbox"
                checked={state.launchAtLogin}
                onChange={() => {
                  void onToggleLaunchAtLogin()
                }}
              />
              <span>Open at Login</span>
            </label>
          )}
        </div>

        {state.endpoint && (
          <button
            type="button"
            className={`endpoint ${copied ? 'endpoint-copied' : ''}`}
            onClick={() => {
              void onCopyEndpoint()
            }}
            title="Copy endpoint URL"
          >
            <span className="endpoint-host">{state.endpoint}</span>
            <span className="endpoint-action">{copied ? 'Copied' : 'Copy'}</span>
          </button>
        )}

        <div className="tabs" role="tablist">
          {state.routers.length === 0 ? (
            <div className="tabs-empty">
              {refreshing ? 'Refreshing routers…' : 'No routers reachable'}
            </div>
          ) : (
            state.routers.map((r) => {
              const isSelected = selectedRouter === r.router
              return (
                <button
                  key={r.router}
                  type="button"
                  role="tab"
                  aria-selected={isSelected}
                  className={`tab ${isSelected ? 'selected' : ''} status-${r.status}`}
                  onClick={() => onSelectRouter(r.router)}
                >
                  <span className={dotForRouter(r)} />
                  <span className="tab-label">{r.label}</span>
                </button>
              )
            })
          )}
          <button
            type="button"
            className={`refresh ${refreshing ? 'refresh-busy' : ''}`}
            onClick={() => {
              void onRefreshRouters()
            }}
            disabled={refreshing}
            title="Refresh router list from atc.tinfoil.sh"
            aria-label="Refresh routers"
          >
            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
              <path d="M21 12a9 9 0 1 1-3.2-6.9" />
              <path d="M21 4v5h-5" />
            </svg>
          </button>
        </div>
      </div>

      <div className="iframe-wrap" aria-hidden={!isExpanded}>
        <iframe
          ref={iframeRef}
          src={iframeUrl}
          title="Tinfoil Verification Center"
          onLoad={() => setIframeReady(true)}
        />
      </div>
    </div>
  )
}
