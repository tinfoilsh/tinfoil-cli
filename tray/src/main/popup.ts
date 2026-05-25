import { join } from 'node:path'
import { BrowserWindow, screen, type Rectangle } from 'electron'

import {
  POPUP_HEIGHT_COMPACT,
  POPUP_HEIGHT_COMPACT_MIN,
  POPUP_HEIGHT_EXPANDED,
  POPUP_WIDTH
} from './constants.js'

let popup: BrowserWindow | undefined
let expanded = false
let compactHeight = POPUP_HEIGHT_COMPACT
let lastTrayBounds: Rectangle | undefined

function rendererEntry(): string {
  if (process.env.ELECTRON_RENDERER_URL) {
    return process.env.ELECTRON_RENDERER_URL
  }
  return join(import.meta.dirname ?? __dirname, '../renderer/index.html')
}

export function getPopup(): BrowserWindow | undefined {
  return popup
}

export function hidePopup(): void {
  if (popup && popup.isVisible()) {
    popup.hide()
  }
}

function createPopup(): BrowserWindow {
  const window = new BrowserWindow({
    width: POPUP_WIDTH,
    height: compactHeight,
    show: false,
    frame: false,
    resizable: false,
    fullscreenable: false,
    movable: false,
    skipTaskbar: true,
    transparent: process.platform === 'darwin',
    vibrancy: process.platform === 'darwin' ? 'menu' : undefined,
    webPreferences: {
      preload: join(import.meta.dirname ?? __dirname, '../preload/index.cjs'),
      sandbox: true,
      contextIsolation: true,
      nodeIntegration: false
    }
  })

  const entry = rendererEntry()
  if (entry.startsWith('http')) {
    void window.loadURL(entry)
  } else {
    void window.loadFile(entry)
  }

  window.on('blur', () => {
    window.hide()
  })

  window.on('closed', () => {
    popup = undefined
  })

  return window
}

function computePopupPosition(
  bounds: Rectangle,
  width: number,
  height: number
): { x: number; y: number } {
  const display = screen.getDisplayMatching(bounds)
  const work = display.workArea
  let x = Math.round(bounds.x + bounds.width / 2 - width / 2)
  let y =
    process.platform === 'win32' ? bounds.y - height - 4 : bounds.y + bounds.height + 4

  if (x + width > work.x + work.width) x = work.x + work.width - width - 4
  if (x < work.x) x = work.x + 4
  if (y + height > work.y + work.height) y = work.y + work.height - height - 4
  if (y < work.y) y = work.y + 4

  return { x, y }
}

function positionUnderTray(window: BrowserWindow, bounds: Rectangle): void {
  const size = window.getSize()
  const w = size[0] ?? POPUP_WIDTH
  const h = size[1] ?? compactHeight
  const { x, y } = computePopupPosition(bounds, w, h)
  window.setBounds({ x, y, width: w, height: h })
}

export function togglePopup(trayBounds: Rectangle): void {
  lastTrayBounds = trayBounds
  if (!popup) {
    popup = createPopup()
  }
  if (popup.isVisible()) {
    popup.hide()
    expanded = false
    popup.setSize(POPUP_WIDTH, compactHeight, false)
    return
  }
  positionUnderTray(popup, trayBounds)
  popup.show()
  popup.focus()
}

export function setPopupExpanded(next: boolean): void {
  if (!popup) return
  if (expanded === next) return
  expanded = next
  const targetH = next ? POPUP_HEIGHT_EXPANDED : compactHeight
  if (lastTrayBounds) {
    const { x, y } = computePopupPosition(lastTrayBounds, POPUP_WIDTH, targetH)
    popup.setBounds({ x, y, width: POPUP_WIDTH, height: targetH }, true)
  } else {
    popup.setSize(POPUP_WIDTH, targetH, true)
  }
}

export function notifyPopup(channel: string, payload: unknown): void {
  if (popup && !popup.isDestroyed()) {
    popup.webContents.send(channel, payload)
  }
}

export function setPopupCompactHeight(rawHeight: number): void {
  const next = Math.max(Math.ceil(rawHeight), POPUP_HEIGHT_COMPACT_MIN)
  if (next === compactHeight) return
  compactHeight = next
  if (popup && !expanded) {
    popup.setSize(POPUP_WIDTH, compactHeight, false)
  }
}
