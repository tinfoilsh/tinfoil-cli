import { useCallback, useEffect, useMemo, useRef, useState } from 'react'

const VERIFICATION_CENTER_BASE_URL = 'https://verification-center.tinfoil.sh'
const VERIFICATION_CENTER_ORIGIN = new URL(VERIFICATION_CENTER_BASE_URL).origin
const SEND_RETRY_DELAYS_MS = [100, 300, 800, 2000]

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
      const next = !state.systemProxy.enabled
      const updated = await window.tinfoil.setSystemProxy(next)
      setState(updated)
      if (!next) setSelectedRouter(null)
    } finally {
      setBusy(false)
    }
  }, [state])

  const onSelectRouter = useCallback((router: string) => {
    setSelectedRouter((prev) => (prev === router ? null : router))
  }, [])

  const [copied, setCopied] = useState(false)
  const onCopyEndpoint = useCallback(async () => {
    const value = await window.tinfoil.copyEndpoint()
    if (!value) return
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }, [])

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

  const active = state.systemProxy.enabled
  const statusTitle = active
    ? state.status === 'failed'
      ? "We couldn't confirm your connection is private"
      : state.status === 'initializing'
        ? 'Setting up your private connection…'
        : "You're protected by Tinfoil"
    : 'Tinfoil is off'
  const statusSub = active
    ? state.routers.length > 0
      ? 'Every API request is routed through an attested enclave whose code and hardware are verified end-to-end.'
      : 'Verifying enclave attestations…'
    : 'Turn this on to route your API requests through attested, verified Tinfoil enclaves.'

  const showWarning = active && state.systemProxy.message

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
            className={`toggle ${active ? 'on' : 'off'}`}
            onClick={onToggleActive}
            disabled={busy}
            aria-pressed={active}
            title={active ? 'Deactivate Tinfoil' : 'Activate Tinfoil'}
          >
            <span className="knob" />
          </button>
        </div>
        {showWarning && <div className="warning">{state.systemProxy.message}</div>}

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
            <div className="tabs-empty">No routers reachable</div>
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
