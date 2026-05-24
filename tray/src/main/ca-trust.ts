import { execFile } from 'node:child_process'
import { existsSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'
import { homedir } from 'node:os'
import { app } from 'electron'

const run = promisify(execFile)

function trustHelperPath(): string | undefined {
  if (process.platform !== 'darwin') return undefined
  const candidates: string[] = []
  if (app.isPackaged) {
    candidates.push(join(process.resourcesPath, 'bin', 'tinfoil-trust'))
  } else {
    const here = dirname(fileURLToPath(import.meta.url))
    candidates.push(resolve(here, '../../../native/build/tinfoil-trust'))
    candidates.push(resolve(here, '../../native/build/tinfoil-trust'))
  }
  return candidates.find((p) => existsSync(p))
}

export interface CaTrustResult {
  ok: boolean
  message?: string
  skipped?: boolean
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
//
// User-level trust: write the cert to the login keychain with `security
// add-trusted-cert`. We first check whether our exact cert is already trusted
// (by SHA-1 fingerprint) so the system password prompt only appears the first
// time Tinfoil is enabled.

const MACOS_LOGIN_KEYCHAIN = `${homedir()}/Library/Keychains/login.keychain-db`
const TINFOIL_CA_COMMON_NAME = 'Tinfoil Tray Local CA'

async function macosCertFingerprint(certPath: string): Promise<string | undefined> {
  try {
    const { stdout } = await run('/usr/bin/openssl', [
      'x509',
      '-in',
      certPath,
      '-noout',
      '-fingerprint',
      '-sha1'
    ])
    const match = stdout.match(/Fingerprint=([A-F0-9:]+)/i)
    return match?.[1]?.replace(/:/g, '').toUpperCase()
  } catch {
    return undefined
  }
}

async function macosAlreadyTrusted(certPath: string): Promise<boolean> {
  const fingerprint = await macosCertFingerprint(certPath)
  if (!fingerprint) return false
  try {
    const { stdout } = await run('/usr/bin/security', [
      'find-certificate',
      '-a',
      '-c',
      TINFOIL_CA_COMMON_NAME,
      '-Z'
    ])
    return stdout.toUpperCase().includes(fingerprint)
  } catch {
    return false
  }
}

async function macosInstall(certPath: string): Promise<CaTrustResult> {
  if (await macosAlreadyTrusted(certPath)) {
    return { ok: true, skipped: true }
  }
  const helper = trustHelperPath()
  if (helper) {
    try {
      await run(helper, ['install', certPath])
      return { ok: true }
    } catch (err) {
      return { ok: false, message: describeError(err) }
    }
  }
  try {
    await run('/usr/bin/security', [
      'add-trusted-cert',
      '-r',
      'trustRoot',
      '-k',
      MACOS_LOGIN_KEYCHAIN,
      certPath
    ])
    return { ok: true }
  } catch (err) {
    return { ok: false, message: describeError(err) }
  }
}

export async function macosIsTrusted(certPath: string): Promise<boolean> {
  const helper = trustHelperPath()
  if (helper) {
    try {
      await run(helper, ['check', certPath])
      return true
    } catch {
      // fall through to the keychain-based check
    }
  }
  return macosAlreadyTrusted(certPath)
}

async function macosRemove(certPath: string): Promise<CaTrustResult> {
  const helper = trustHelperPath()
  if (helper) {
    try {
      await run(helper, ['uninstall', certPath])
      return { ok: true }
    } catch (err) {
      return { ok: false, message: describeError(err) }
    }
  }
  try {
    await run('/usr/bin/security', ['remove-trusted-cert', certPath])
  } catch {
    // remove-trusted-cert is best-effort; not all macOS versions support it
  }
  try {
    await run('/usr/bin/security', ['delete-certificate', '-c', 'Tinfoil Tray Local CA'])
    return { ok: true }
  } catch (err) {
    return { ok: false, message: describeError(err) }
  }
}

// ─── Linux ────────────────────────────────────────────────────────────────────
//
// Per-user NSS DB (used by Chrome, Chromium, Firefox-with-nss): write to
// `~/.pki/nssdb` via `certutil`. System-wide trust requires sudo and is left
// as a manual instruction.

async function linuxInstall(certPath: string): Promise<CaTrustResult> {
  const nssdb = `sql:${homedir()}/.pki/nssdb`
  try {
    await run('certutil', ['-d', nssdb, '-A', '-t', 'C,,', '-n', 'Tinfoil Tray Local CA', '-i', certPath])
    return { ok: true }
  } catch (err) {
    return {
      ok: false,
      message:
        'Could not install CA into ~/.pki/nssdb (certutil missing or NSS DB not initialized). ' +
        `Install manually with: sudo cp ${certPath} /usr/local/share/ca-certificates/tinfoil-tray.crt && sudo update-ca-certificates. ` +
        describeError(err)
    }
  }
}

async function linuxRemove(): Promise<CaTrustResult> {
  const nssdb = `sql:${homedir()}/.pki/nssdb`
  try {
    await run('certutil', ['-d', nssdb, '-D', '-n', 'Tinfoil Tray Local CA'])
    return { ok: true }
  } catch (err) {
    return { ok: false, message: describeError(err) }
  }
}

// ─── Windows ──────────────────────────────────────────────────────────────────
//
// Per-user trust: `certutil -user -addstore Root` writes to
// HKCU\SOFTWARE\Microsoft\SystemCertificates\Root. No admin needed.

async function windowsInstall(certPath: string): Promise<CaTrustResult> {
  try {
    await run('certutil.exe', ['-user', '-addstore', 'Root', certPath])
    return { ok: true }
  } catch (err) {
    return { ok: false, message: describeError(err) }
  }
}

async function windowsRemove(): Promise<CaTrustResult> {
  try {
    await run('certutil.exe', ['-user', '-delstore', 'Root', 'Tinfoil Tray Local CA'])
    return { ok: true }
  } catch (err) {
    return { ok: false, message: describeError(err) }
  }
}

// ─── Dispatch ─────────────────────────────────────────────────────────────────

export async function installCaTrust(certPath: string): Promise<CaTrustResult> {
  switch (process.platform) {
    case 'darwin':
      return macosInstall(certPath)
    case 'linux':
      return linuxInstall(certPath)
    case 'win32':
      return windowsInstall(certPath)
    default:
      return { ok: false, message: `Unsupported platform: ${process.platform}` }
  }
}

export async function removeCaTrust(certPath: string): Promise<CaTrustResult> {
  switch (process.platform) {
    case 'darwin':
      return macosRemove(certPath)
    case 'linux':
      return linuxRemove()
    case 'win32':
      return windowsRemove()
    default:
      return { ok: true }
  }
}
