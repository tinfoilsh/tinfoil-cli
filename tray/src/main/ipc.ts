import { clipboard, ipcMain } from 'electron'

import { loadConfig, saveConfig } from './config.js'
import { PROXY_DEFAULT_PORT } from './constants.js'
import { applyLaunchAtLogin, isLaunchAtLoginSupported } from './login-item.js'
import { notifyPopup, setPopupCompactHeight, setPopupExpanded } from './popup.js'
import { proxyEndpoint, startProxy, stopProxy } from './proxy.js'
import { refreshRouters } from './secure-client.js'
import { stateStore, type TrayState } from './state.js'

function snapshotForRenderer(state: TrayState) {
  const sortedRouters = [...state.routers].sort((a, b) => a.router.localeCompare(b.router))
  const anonymized = sortedRouters.map((r, index) => ({
    router: r.router,
    label: `Router ${index + 1}`,
    status: r.status,
    lastError: r.lastError,
    document: r.document ?? null
  }))

  const endpoint =
    state.proxy.enabled && state.proxy.running && state.proxy.port > 0
      ? proxyEndpoint(state.proxy.port)
      : undefined

  return {
    status: state.status,
    statusMessage: state.statusMessage,
    routers: anonymized,
    endpoint,
    proxy: state.proxy,
    launchAtLogin: state.launchAtLogin,
    launchAtLoginSupported: isLaunchAtLoginSupported(),
    lastError: state.lastError
  }
}

function clampPort(value: unknown): number | null {
  const port = typeof value === 'number' ? value : Number(value)
  if (!Number.isFinite(port) || !Number.isInteger(port)) return null
  if (port < 1 || port > 65535) return null
  return port
}

export function registerIpc(): void {
  ipcMain.handle('tray:getState', () => snapshotForRenderer(stateStore.get()))

  ipcMain.handle('tray:copyEndpoint', () => {
    const snap = snapshotForRenderer(stateStore.get())
    if (!snap.endpoint) return null
    clipboard.writeText(snap.endpoint)
    return snap.endpoint
  })

  ipcMain.handle('tray:setProxyEnabled', async (_event, enabled: boolean) => {
    const cfg = await loadConfig()
    const nextEnabled = !!enabled
    if (nextEnabled) {
      await startProxy(cfg.port || PROXY_DEFAULT_PORT)
    } else {
      await stopProxy()
      const current = stateStore.get().proxy
      stateStore.set({
        proxy: { ...current, enabled: false, running: false, lastError: undefined }
      })
    }
    await saveConfig({ ...cfg, proxyEnabled: nextEnabled })
    return snapshotForRenderer(stateStore.get())
  })

  ipcMain.handle('tray:setProxyPort', async (_event, port: unknown) => {
    const clamped = clampPort(port)
    if (clamped === null) return snapshotForRenderer(stateStore.get())
    const cfg = await loadConfig()
    await saveConfig({ ...cfg, port: clamped })
    const proxy = stateStore.get().proxy
    if (proxy.enabled) {
      await startProxy(clamped)
    } else {
      stateStore.set({ proxy: { ...proxy, port: clamped } })
    }
    return snapshotForRenderer(stateStore.get())
  })

  ipcMain.handle('tray:refreshRouters', async () => {
    await refreshRouters()
    return snapshotForRenderer(stateStore.get())
  })

  ipcMain.handle('tray:setLaunchAtLogin', async (_event, enabled: boolean) => {
    const next = !!enabled
    const cfg = await loadConfig()
    await saveConfig({ ...cfg, launchAtLogin: next })
    applyLaunchAtLogin(next)
    stateStore.set({ launchAtLogin: next })
    return snapshotForRenderer(stateStore.get())
  })

  ipcMain.handle('tray:setExpanded', (_event, expanded: boolean) => {
    setPopupExpanded(!!expanded)
  })

  ipcMain.handle('tray:setCompactHeight', (_event, height: number) => {
    if (typeof height === 'number' && Number.isFinite(height)) {
      setPopupCompactHeight(height)
    }
  })

  stateStore.onChange((state) => {
    notifyPopup('tray:stateChanged', snapshotForRenderer(state))
  })
}
