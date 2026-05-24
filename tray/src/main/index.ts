import { app } from 'electron'

import { loadConfig } from './config.js'
import { ROUTERS_REFRESH_INTERVAL_MS } from './constants.js'
import { registerIpc } from './ipc.js'
import { createTray } from './menu.js'
import { startProxy, stopProxy } from './proxy.js'
import { fetchRouters } from './routers.js'
import { activateRouters, disposeSecureClients } from './secure-client.js'
import { stateStore } from './state.js'
import { startAutoUpdater, stopAutoUpdater } from './updater.js'

let routersTimer: NodeJS.Timeout | undefined

if (process.platform === 'darwin') {
  app.dock?.hide()
}

const singleInstance = app.requestSingleInstanceLock()
if (!singleInstance) {
  app.quit()
}

async function refreshRouters(): Promise<void> {
  try {
    const routers = await fetchRouters()
    await activateRouters(routers)
  } catch (err) {
    stateStore.set({ lastError: `Could not fetch routers: ${(err as Error).message}` })
  }
}

async function bootstrap(): Promise<void> {
  registerIpc()
  createTray()

  const cfg = await loadConfig()
  stateStore.set({
    proxy: {
      enabled: cfg.proxyEnabled,
      running: false,
      port: cfg.port,
      lastError: undefined
    }
  })

  if (cfg.proxyEnabled) {
    await startProxy(cfg.port)
  }

  void refreshRouters()

  routersTimer = setInterval(() => {
    void refreshRouters()
  }, ROUTERS_REFRESH_INTERVAL_MS)

  startAutoUpdater()
}

app.whenReady().then(() => {
  void bootstrap()
})

app.on('window-all-closed', () => {
  // Tray app: keep alive when the popup is closed.
})

app.on('before-quit', async (event) => {
  event.preventDefault()
  if (routersTimer) clearInterval(routersTimer)
  stopAutoUpdater()
  disposeSecureClients()
  await stopProxy()
  app.exit(0)
})
