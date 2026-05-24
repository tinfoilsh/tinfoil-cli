import { createHash } from 'node:crypto'
import { promises as fs } from 'node:fs'
import { join } from 'node:path'
import type { SecureContext } from 'node:tls'
import { createSecureContext } from 'node:tls'

import { app } from 'electron'
import forge from 'node-forge'

const CA_DIR = 'ca'
const CA_CERT_FILE = 'tinfoil-tray-ca.pem'
const CA_KEY_FILE = 'tinfoil-tray-ca.key'
const CA_COMMON_NAME = 'Tinfoil Tray Local CA'
const CA_ORG = 'Tinfoil Tray'
const CA_VALIDITY_YEARS = 10
const LEAF_VALIDITY_DAYS = 397

export interface CaMaterial {
  certPem: string
  keyPem: string
  fingerprintSha256: string
  certPath: string
  cert: forge.pki.Certificate
  key: forge.pki.rsa.PrivateKey
}

let cached: CaMaterial | undefined
const leafContextCache = new Map<string, SecureContext>()

function userDataDir(): string {
  return join(app.getPath('userData'), CA_DIR)
}

function makeSerial(): string {
  const bytes = forge.random.getBytesSync(16)
  let hex = forge.util.bytesToHex(bytes)
  if ((parseInt(hex[0]!, 16) & 0x8) !== 0) {
    hex = '0' + hex.slice(1)
  }
  return hex
}

function sha256Fp(certPem: string): string {
  const der = forge.asn1.toDer(forge.pki.certificateToAsn1(forge.pki.certificateFromPem(certPem))).getBytes()
  return createHash('sha256').update(Buffer.from(der, 'binary')).digest('hex').match(/.{2}/g)!.join(':').toUpperCase()
}

function generateCa(): { certPem: string; keyPem: string; cert: forge.pki.Certificate; key: forge.pki.rsa.PrivateKey } {
  const keys = forge.pki.rsa.generateKeyPair(2048)
  const cert = forge.pki.createCertificate()
  cert.publicKey = keys.publicKey
  cert.serialNumber = makeSerial()
  cert.validity.notBefore = new Date()
  cert.validity.notAfter = new Date(cert.validity.notBefore.getTime())
  cert.validity.notAfter.setFullYear(cert.validity.notAfter.getFullYear() + CA_VALIDITY_YEARS)
  const attrs: forge.pki.CertificateField[] = [
    { name: 'commonName', value: CA_COMMON_NAME },
    { name: 'organizationName', value: CA_ORG }
  ]
  cert.setSubject(attrs)
  cert.setIssuer(attrs)
  cert.setExtensions([
    { name: 'basicConstraints', cA: true, critical: true },
    { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true },
    { name: 'subjectKeyIdentifier' }
  ])
  cert.sign(keys.privateKey, forge.md.sha256.create())
  return {
    certPem: forge.pki.certificateToPem(cert),
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
    cert,
    key: keys.privateKey
  }
}

export async function ensureCa(): Promise<CaMaterial> {
  if (cached) return cached
  const dir = userDataDir()
  await fs.mkdir(dir, { recursive: true })
  const certPath = join(dir, CA_CERT_FILE)
  const keyPath = join(dir, CA_KEY_FILE)
  try {
    const [certPem, keyPem] = await Promise.all([
      fs.readFile(certPath, 'utf8'),
      fs.readFile(keyPath, 'utf8')
    ])
    const cert = forge.pki.certificateFromPem(certPem)
    const key = forge.pki.privateKeyFromPem(keyPem) as forge.pki.rsa.PrivateKey
    cached = { certPem, keyPem, cert, key, certPath, fingerprintSha256: sha256Fp(certPem) }
    return cached
  } catch {
    // generate fresh
  }
  const generated = generateCa()
  await Promise.all([
    fs.writeFile(certPath, generated.certPem, { mode: 0o644 }),
    fs.writeFile(keyPath, generated.keyPem, { mode: 0o600 })
  ])
  cached = {
    certPem: generated.certPem,
    keyPem: generated.keyPem,
    cert: generated.cert,
    key: generated.key,
    certPath,
    fingerprintSha256: sha256Fp(generated.certPem)
  }
  return cached
}

function mintLeaf(ca: CaMaterial, hostname: string): { certPem: string; keyPem: string } {
  const keys = forge.pki.rsa.generateKeyPair(2048)
  const cert = forge.pki.createCertificate()
  cert.publicKey = keys.publicKey
  cert.serialNumber = makeSerial()
  cert.validity.notBefore = new Date(Date.now() - 60_000)
  cert.validity.notAfter = new Date(Date.now() + LEAF_VALIDITY_DAYS * 86_400_000)
  cert.setSubject([{ name: 'commonName', value: hostname }])
  cert.setIssuer(ca.cert.subject.attributes)
  cert.setExtensions([
    { name: 'basicConstraints', cA: false },
    {
      name: 'keyUsage',
      digitalSignature: true,
      keyEncipherment: true,
      critical: true
    },
    {
      name: 'extKeyUsage',
      serverAuth: true,
      clientAuth: true
    },
    {
      name: 'subjectAltName',
      altNames: [{ type: 2, value: hostname }]
    }
  ])
  cert.sign(ca.key, forge.md.sha256.create())
  return {
    certPem: forge.pki.certificateToPem(cert),
    keyPem: forge.pki.privateKeyToPem(keys.privateKey)
  }
}

export async function leafContextFor(hostname: string): Promise<SecureContext> {
  const cached = leafContextCache.get(hostname)
  if (cached) return cached
  const ca = await ensureCa()
  const { certPem, keyPem } = mintLeaf(ca, hostname)
  const ctx = createSecureContext({
    cert: certPem,
    key: keyPem,
    ca: ca.certPem
  })
  leafContextCache.set(hostname, ctx)
  return ctx
}

export function clearLeafCache(): void {
  leafContextCache.clear()
}
