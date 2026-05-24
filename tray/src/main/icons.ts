import { join } from 'node:path'
import { app, nativeImage, type NativeImage } from 'electron'

import type { VerificationStatus } from './state.js'

export type TrayIconState = 'off' | 'verified' | 'initializing' | 'failed'

function assetPath(name: string): string {
  if (app.isPackaged) {
    return join(process.resourcesPath, 'assets', name)
  }
  return join(app.getAppPath(), 'assets', name)
}

export function trayIconState(active: boolean, status: VerificationStatus): TrayIconState {
  if (!active) return 'off'
  if (status === 'failed') return 'failed'
  if (status === 'verified') return 'verified'
  return 'initializing'
}

export function trayIcon(state: TrayIconState): NativeImage {
  let base: string
  switch (state) {
    case 'failed':
      base = 'icon-tray-error-Template'
      break
    case 'verified':
    case 'initializing':
      base = 'icon-tray-on-Template'
      break
    case 'off':
    default:
      base = 'icon-tray-off-Template'
      break
  }
  const image = nativeImage.createFromPath(assetPath(`${base}.png`))
  image.setTemplateImage(true)
  return image
}
