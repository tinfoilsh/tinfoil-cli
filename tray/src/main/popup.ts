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

function positionUnderTray(window: BrowserWindow, bounds: Rectangle): void {
  const display = screen.getDisplayMatching(bounds)
  const work = display.workArea
  const size = window.getSize()
  const w = size[0] ?? POPUP_WIDTH
  const h = size[1] ?? compactHeight
  let x = Math.round(bounds.x + bounds.width / 2 - w / 2)
  let y = bounds.y + bounds.height + 4

  if (process.platform === 'win32') {
    x = Math.round(bounds.x + bounds.width / 2 - w / 2)
    y = bounds.y - h - 4
  }

  if (x + w > work.x + work.width) x = work.x + work.width - w - 4
  if (x < work.x) x = work.x + 4
  if (y + h > work.y + work.height) y = work.y + work.height - h - 4
  if (y < work.y) y = work.y + 4

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
    const display = screen.getDisplayMatching(lastTrayBounds)
    const work = display.workArea
    const w = POPUP_WIDTH
    let x = Math.round(lastTrayBounds.x + lastTrayBounds.width / 2 - w / 2)
    let y = lastTrayBounds.y + lastTrayBounds.height + 4
    if (process.platform === 'win32') {
      y = lastTrayBounds.y - targetH - 4
    }
    if (x + w > work.x + work.width) x = work.x + work.width - w - 4
    if (x < work.x) x = work.x + 4
    if (y + targetH > work.y + work.height) y = work.y + work.height - targetH - 4
    if (y < work.y) y = work.y + 4
    popup.setBounds({ x, y, width: w, height: targetH }, true)
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
