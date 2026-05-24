import { app, clipboard, Menu, type MenuItemConstructorOptions, Tray, type Rectangle } from 'electron'

import { loadConfig, saveConfig } from './config.js'
import { LOCAL_ENDPOINT_URL } from './constants.js'
import { trayIcon, trayIconState } from './icons.js'
import { disableMagicMode, enableMagicMode } from './magic.js'
import { hidePopup, togglePopup } from './popup.js'
import { stateStore, type TrayState, type RouterState } from './state.js'

let tray: Tray | undefined
let contextMenu: Menu | undefined

function isActive(state: TrayState): boolean {
  return state.systemProxy.enabled
}

function headerLabel(state: TrayState): string {
  if (!isActive(state)) return '● Tinfoil — Not active'
  switch (state.status) {
    case 'verified':
      return '● Tinfoil — Active'
    case 'failed':
      return '● Tinfoil — Active (attestation failed)'
    case 'initializing':
    default:
      return '○ Tinfoil — Activating…'
  }
}

function routerLine(r: RouterState, index: number): string {
  const symbol = r.status === 'verified' ? '✓' : r.status === 'failed' ? '✗' : '…'
  return `  ${symbol}  Router ${index + 1}`
}

function sortedRouters(state: TrayState): RouterState[] {
  return [...state.routers].sort((a, b) => a.router.localeCompare(b.router))
}

function buildMenu(state: TrayState, openDetails: () => void): Menu {
  const active = isActive(state)
  const items: MenuItemConstructorOptions[] = [
    { label: headerLabel(state), enabled: false },
    { type: 'separator' },
    {
      label: active ? 'Deactivate Tinfoil' : 'Activate Tinfoil',
      click: () => {
        void toggle(!active)
      }
    },
    {
      label: 'Show verification details…',
      click: openDetails
    }
  ]

  if (state.endpoint) {
    items.push({
      label: `Copy ${LOCAL_ENDPOINT_URL}`,
      click: () => {
        clipboard.writeText(LOCAL_ENDPOINT_URL)
      }
    })
  }

  items.push(
    { type: 'separator' },
    { label: 'Routers', enabled: false },
    ...sortedRouters(state).map<MenuItemConstructorOptions>((r, idx) => ({
      label: routerLine(r, idx),
      enabled: false
    }))
  )

  if (state.systemProxy.message) {
    items.push({ type: 'separator' }, { label: `Note: ${state.systemProxy.message}`, enabled: false })
  } else if (state.lastError && !active) {
    items.push({ type: 'separator' }, { label: `Note: ${state.lastError}`, enabled: false })
  }

  items.push(
    { type: 'separator' },
    {
      label: 'Quit Tinfoil',
      click: () => {
        app.quit()
      }
    }
  )

  return Menu.buildFromTemplate(items)
}

async function toggle(enable: boolean): Promise<void> {
  const result = enable ? await enableMagicMode() : await disableMagicMode()
  const cfg = await loadConfig()
  await saveConfig({ ...cfg, systemProxyEnabled: result.ok && enable })
}

export function createTray(): Tray {
  if (tray) return tray
  const initial = trayIcon(trayIconState(false, 'initializing'))
  tray = new Tray(initial)
  tray.setToolTip('Tinfoil')

  const refresh = () => {
    if (!tray) return
    const state = stateStore.get()
    const active = isActive(state)
    tray.setImage(trayIcon(trayIconState(active, state.status)))
    tray.setToolTip(active ? `Tinfoil — ${state.statusMessage}` : 'Tinfoil — Not active')
    contextMenu = buildMenu(state, () => {
      if (!tray) return
      togglePopup(tray.getBounds())
    })
  }

  refresh()
  stateStore.onChange(refresh)

  tray.on('click', (_event: Electron.KeyboardEvent, bounds: Rectangle) => {
    togglePopup(bounds)
  })

  tray.on('right-click', () => {
    if (!tray || !contextMenu) return
    hidePopup()
    tray.popUpContextMenu(contextMenu)
  })

  return tray
}
