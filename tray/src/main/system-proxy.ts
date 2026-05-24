import { execFile, type ExecFileException } from 'node:child_process'
import { promisify } from 'node:util'

const run = promisify(execFile)

export interface SystemProxyResult {
  ok: boolean
  message?: string
}

interface ExecError {
  stdout?: string
  stderr?: string
  message?: string
}

function describeError(err: unknown): string {
  const e = err as ExecError
  return (e?.stderr || e?.stdout || e?.message || String(err)).trim()
}

// ─── macOS ────────────────────────────────────────────────────────────────────

async function macosNetworkServices(): Promise<string[]> {
  const { stdout } = await run('/usr/sbin/networksetup', ['-listallnetworkservices'])
  return stdout
    .split('\n')
    .slice(1)
    .map((s) => s.trim())
    .filter((s) => s.length > 0 && !s.startsWith('*'))
}

async function macosEnable(pacUrl: string): Promise<SystemProxyResult> {
  try {
    const services = await macosNetworkServices()
    if (services.length === 0) {
      return { ok: false, message: 'No network services found' }
    }
    for (const service of services) {
      await run('/usr/sbin/networksetup', ['-setautoproxyurl', service, pacUrl])
      await run('/usr/sbin/networksetup', ['-setautoproxystate', service, 'on'])
    }
    return { ok: true }
  } catch (err) {
    return { ok: false, message: describeError(err) }
  }
}

async function macosDisable(): Promise<SystemProxyResult> {
  try {
    const services = await macosNetworkServices()
    for (const service of services) {
      try {
        await run('/usr/sbin/networksetup', ['-setautoproxystate', service, 'off'])
      } catch {
        // ignore per-service failures
      }
    }
    return { ok: true }
  } catch (err) {
    return { ok: false, message: describeError(err) }
  }
}

// ─── Linux (GNOME) ────────────────────────────────────────────────────────────

async function linuxEnable(pacUrl: string): Promise<SystemProxyResult> {
  try {
    await run('gsettings', ['set', 'org.gnome.system.proxy', 'mode', 'auto'])
    await run('gsettings', ['set', 'org.gnome.system.proxy', 'autoconfig-url', pacUrl])
    return { ok: true }
  } catch (err) {
    return {
      ok: false,
      message:
        'Could not configure system proxy via gsettings (GNOME only). ' +
        'Set PAC URL manually: ' +
        pacUrl +
        '. ' +
        describeError(err)
    }
  }
}

async function linuxDisable(): Promise<SystemProxyResult> {
  try {
    await run('gsettings', ['set', 'org.gnome.system.proxy', 'mode', 'none'])
    return { ok: true }
  } catch (err) {
    return { ok: false, message: describeError(err) }
  }
}

// ─── Windows ──────────────────────────────────────────────────────────────────
//
// Per-user WinINet config lives at HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings.
// We use PowerShell so we get proper REG_SZ values and avoid escaping pain.

async function powershell(script: string): Promise<void> {
  await run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script])
}

async function windowsEnable(pacUrl: string): Promise<SystemProxyResult> {
  try {
    const escaped = pacUrl.replace(/'/g, "''")
    await powershell(
      `$key = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
       Set-ItemProperty -Path $key -Name AutoConfigURL -Value '${escaped}';
       Set-ItemProperty -Path $key -Name ProxyEnable -Value 0;`
    )
    return { ok: true }
  } catch (err) {
    return { ok: false, message: describeError(err) }
  }
}

async function windowsDisable(): Promise<SystemProxyResult> {
  try {
    await powershell(
      `$key = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings';
       Remove-ItemProperty -Path $key -Name AutoConfigURL -ErrorAction SilentlyContinue;`
    )
    return { ok: true }
  } catch (err) {
    return { ok: false, message: describeError(err) }
  }
}

// ─── Dispatch ─────────────────────────────────────────────────────────────────

export async function enableSystemProxy(pacUrl: string): Promise<SystemProxyResult> {
  switch (process.platform) {
    case 'darwin':
      return macosEnable(pacUrl)
    case 'linux':
      return linuxEnable(pacUrl)
    case 'win32':
      return windowsEnable(pacUrl)
    default:
      return {
        ok: false,
        message: `Unsupported platform: ${process.platform}. PAC URL: ${pacUrl}`
      }
  }
}

export async function disableSystemProxy(): Promise<SystemProxyResult> {
  switch (process.platform) {
    case 'darwin':
      return macosDisable()
    case 'linux':
      return linuxDisable()
    case 'win32':
      return windowsDisable()
    default:
      return { ok: true }
  }
}

// Compatibility shim so this file passes `tsc --strict` even with the
// `ExecFileException` import unused if Node typings change.
export type _UnusedExecError = ExecFileException
