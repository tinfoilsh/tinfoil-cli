import { clipboard, ipcMain } from 'electron'

import { loadConfig, saveConfig } from './config.js'
import { LOCAL_ENDPOINT_URL } from './constants.js'
import { disableMagicMode, enableMagicMode } from './magic.js'
import { notifyPopup, setPopupCompactHeight, setPopupExpanded } from './popup.js'
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

  return {
    status: state.status,
    statusMessage: state.statusMessage,
    routers: anonymized,
    endpoint: state.endpoint,
    port: state.port,
    systemProxy: state.systemProxy,
    lastError: state.lastError
  }
}

export function registerIpc(): void {
  ipcMain.handle('tray:getState', () => snapshotForRenderer(stateStore.get()))

  ipcMain.handle('tray:copyEndpoint', () => {
    if (!stateStore.get().endpoint) return null
    clipboard.writeText(LOCAL_ENDPOINT_URL)
    return LOCAL_ENDPOINT_URL
  })

  ipcMain.handle('tray:setSystemProxy', async (_event, enable: boolean) => {
    const result = enable ? await enableMagicMode() : await disableMagicMode()
    const cfg = await loadConfig()
    await saveConfig({ ...cfg, systemProxyEnabled: result.ok && enable })
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
