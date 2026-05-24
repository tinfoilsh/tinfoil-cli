import { contextBridge, ipcRenderer } from 'electron'

export interface RouterSnapshot {
  router: string
  label: string
  status: 'initializing' | 'verified' | 'failed'
  lastError?: string
  document: unknown | null
}

export interface ProxySnapshot {
  enabled: boolean
  running: boolean
  port: number
  lastError?: string
}

export interface TrayStateSnapshot {
  status: 'initializing' | 'verified' | 'failed'
  statusMessage: string
  routers: RouterSnapshot[]
  endpoint?: string
  proxy: ProxySnapshot
  launchAtLogin: boolean
  launchAtLoginSupported: boolean
  lastError?: string
}

const api = {
  getState: (): Promise<TrayStateSnapshot> => ipcRenderer.invoke('tray:getState'),
  copyEndpoint: (): Promise<string | null> => ipcRenderer.invoke('tray:copyEndpoint'),
  setProxyEnabled: (enabled: boolean): Promise<TrayStateSnapshot> =>
    ipcRenderer.invoke('tray:setProxyEnabled', enabled),
  setProxyPort: (port: number): Promise<TrayStateSnapshot> =>
    ipcRenderer.invoke('tray:setProxyPort', port),
  refreshRouters: (): Promise<TrayStateSnapshot> =>
    ipcRenderer.invoke('tray:refreshRouters'),
  setLaunchAtLogin: (enabled: boolean): Promise<TrayStateSnapshot> =>
    ipcRenderer.invoke('tray:setLaunchAtLogin', enabled),
  setExpanded: (expanded: boolean): Promise<void> =>
    ipcRenderer.invoke('tray:setExpanded', expanded),
  setCompactHeight: (height: number): Promise<void> =>
    ipcRenderer.invoke('tray:setCompactHeight', height),
  onStateChanged: (handler: (state: TrayStateSnapshot) => void): (() => void) => {
    const listener = (_event: Electron.IpcRendererEvent, state: TrayStateSnapshot) =>
      handler(state)
    ipcRenderer.on('tray:stateChanged', listener)
    return () => ipcRenderer.off('tray:stateChanged', listener)
  }
}

contextBridge.exposeInMainWorld('tinfoil', api)

export type TinfoilApi = typeof api
