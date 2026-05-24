import { app } from 'electron'

const SUPPORTED = process.platform === 'darwin' || process.platform === 'win32'

export function applyLaunchAtLogin(enabled: boolean): void {
  if (!SUPPORTED) return
  app.setLoginItemSettings({
    openAtLogin: enabled,
    openAsHidden: true
  })
}

export function getLaunchAtLogin(): boolean {
  if (!SUPPORTED) return false
  return app.getLoginItemSettings().openAtLogin
}

export function isLaunchAtLoginSupported(): boolean {
  return SUPPORTED
}
