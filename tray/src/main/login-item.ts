import { app } from 'electron'

const PLATFORM_SUPPORTED = process.platform === 'darwin' || process.platform === 'win32'

function canManageLoginItem(): boolean {
  return PLATFORM_SUPPORTED && app.isPackaged
}

export function applyLaunchAtLogin(enabled: boolean): void {
  if (!canManageLoginItem()) return
  app.setLoginItemSettings({
    openAtLogin: enabled,
    openAsHidden: true
  })
}

export function getLaunchAtLogin(): boolean {
  if (!canManageLoginItem()) return false
  return app.getLoginItemSettings().openAtLogin
}

export function isLaunchAtLoginSupported(): boolean {
  return canManageLoginItem()
}
