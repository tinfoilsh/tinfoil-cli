import { dialog } from 'electron'

import { ensureCa } from './ca.js'
import { installCaTrust, macosIsTrusted, removeCaTrust } from './ca-trust.js'
import { pacUrl } from './proxy.js'
import { getPopup } from './popup.js'
import { stateStore } from './state.js'
import { disableSystemProxy, enableSystemProxy } from './system-proxy.js'

async function confirmTrustInstall(): Promise<boolean> {
  const parent = getPopup()
  const choice = await dialog.showMessageBox(parent && !parent.isDestroyed() ? parent : undefined as never, {
    type: 'info',
    title: 'Trust the Tinfoil local certificate authority?',
    message: 'Tinfoil needs to trust its local certificate authority.',
    detail:
      'This lets every browser, terminal, and app on this Mac route traffic through the attested Tinfoil proxy without certificate warnings.\n\nmacOS will ask for your password next. You only need to do this once.',
    buttons: ['Continue', 'Cancel'],
    defaultId: 0,
    cancelId: 1,
    noLink: true
  })
  return choice.response === 0
}

export async function enableMagicMode(): Promise<{ ok: boolean; message?: string }> {
  const url = pacUrl()
  if (!url) {
    stateStore.set({
      systemProxy: {
        enabled: false,
        trusted: false,
        message: 'Proxy is not listening yet'
      }
    })
    return { ok: false, message: 'Proxy is not listening yet' }
  }

  const ca = await ensureCa()

  if (process.platform === 'darwin') {
    const alreadyTrusted = await macosIsTrusted(ca.certPath)
    if (!alreadyTrusted) {
      const confirmed = await confirmTrustInstall()
      if (!confirmed) {
        stateStore.set({
          systemProxy: {
            enabled: false,
            trusted: false,
            caCertPath: ca.certPath,
            message: undefined
          }
        })
        return { ok: false, message: 'Cancelled' }
      }
    }
  }

  const trust = await installCaTrust(ca.certPath)

  if (!trust.ok) {
    stateStore.set({
      systemProxy: {
        enabled: false,
        trusted: false,
        caCertPath: ca.certPath,
        message: `Trust not granted: ${trust.message ?? 'cancelled'}`
      }
    })
    return { ok: false, message: trust.message }
  }

  const proxyResult = await enableSystemProxy(url)
  if (!proxyResult.ok) {
    await removeCaTrust(ca.certPath)
    stateStore.set({
      systemProxy: {
        enabled: false,
        trusted: false,
        caCertPath: ca.certPath,
        message: `Could not register system proxy: ${proxyResult.message ?? ''}`.trim()
      }
    })
    return { ok: false, message: proxyResult.message }
  }

  stateStore.set({
    systemProxy: {
      enabled: true,
      trusted: true,
      pacUrl: url,
      caCertPath: ca.certPath,
      message: undefined
    }
  })

  return { ok: true }
}

export async function disableMagicMode(): Promise<{ ok: boolean; message?: string }> {
  const ca = await ensureCa()
  const proxyResult = await disableSystemProxy()

  stateStore.set({
    systemProxy: {
      enabled: false,
      trusted: stateStore.get().systemProxy.trusted,
      pacUrl: undefined,
      caCertPath: ca.certPath,
      message: proxyResult.ok ? undefined : `Proxy: ${proxyResult.message}`
    }
  })

  return { ok: proxyResult.ok, message: proxyResult.message }
}

export async function uninstallTrust(): Promise<{ ok: boolean; message?: string }> {
  const ca = await ensureCa()
  const result = await removeCaTrust(ca.certPath)
  stateStore.set({
    systemProxy: {
      ...stateStore.get().systemProxy,
      trusted: !result.ok ? stateStore.get().systemProxy.trusted : false
    }
  })
  return result
}
