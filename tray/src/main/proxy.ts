import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http'
import { createServer as createHttpsServer } from 'node:https'
import { Readable } from 'node:stream'
import type { Socket } from 'node:net'

import { leafContextFor } from './ca.js'
import {
  HOP_BY_HOP_HEADERS,
  LOCAL_ENDPOINT_URL,
  PROXY_LISTEN_HOST,
  PROXY_PORT_MAX_ATTEMPTS
} from './constants.js'
import { getClient, knownRouters, pickRoundRobinRouter } from './secure-client.js'
import { stateStore } from './state.js'

let server: Server | undefined
let httpsHandler: ReturnType<typeof createHttpsServer> | undefined

function buildHeaders(req: IncomingMessage): Headers {
  const headers = new Headers()
  for (const [key, value] of Object.entries(req.headers)) {
    if (value === undefined) continue
    if (HOP_BY_HOP_HEADERS.has(key.toLowerCase())) continue
    if (Array.isArray(value)) {
      for (const v of value) headers.append(key, v)
    } else {
      headers.set(key, value)
    }
  }
  return headers
}

function requestHasBody(method: string): boolean {
  return method !== 'GET' && method !== 'HEAD'
}

function resolveRouter(req: IncomingMessage, forceHost?: string): string | undefined {
  if (forceHost) return forceHost
  const hostHeader = req.headers.host
  if (hostHeader) {
    const bare = hostHeader.split(':')[0]
    if (bare && knownRouters().includes(bare)) return bare
  }
  return pickRoundRobinRouter()
}

function pacFile(): string {
  const hosts = knownRouters()
  const listEntries = hosts.map((h) => `    "${h}": 1`).join(',\n')
  const port = stateStore.get().port
  return `function FindProxyForURL(url, host) {
  var routers = {
${listEntries}
  };
  if (routers[host]) {
    return "PROXY ${PROXY_LISTEN_HOST}:${port}";
  }
  return "DIRECT";
}
`
}

async function handle(req: IncomingMessage, res: ServerResponse, forceHost?: string): Promise<void> {
  if (req.url === '/proxy.pac' && !forceHost) {
    res.statusCode = 200
    res.setHeader('Content-Type', 'application/x-ns-proxy-autoconfig')
    res.setHeader('Cache-Control', 'no-store')
    res.end(pacFile())
    return
  }

  const router = resolveRouter(req, forceHost)
  if (!router) {
    res.statusCode = 503
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ error: 'Tinfoil tray is still verifying the enclave' }))
    return
  }
  const client = getClient(router)
  if (!client) {
    res.statusCode = 502
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ error: `Unknown router ${router}` }))
    return
  }

  const url = req.url ?? '/'
  const method = (req.method ?? 'GET').toUpperCase()
  const init: RequestInit = {
    method,
    headers: buildHeaders(req)
  }
  if (requestHasBody(method)) {
    ;(init as unknown as { body: unknown }).body = Readable.toWeb(req)
    ;(init as unknown as { duplex: string }).duplex = 'half'
  }

  let upstream: Response
  try {
    upstream = await client.fetch(url, init)
  } catch (err) {
    res.statusCode = 502
    res.setHeader('Content-Type', 'application/json')
    res.end(JSON.stringify({ error: 'Upstream request failed', detail: String(err) }))
    return
  }

  res.statusCode = upstream.status
  upstream.headers.forEach((value, key) => {
    if (HOP_BY_HOP_HEADERS.has(key.toLowerCase())) return
    res.setHeader(key, value)
  })

  if (upstream.body) {
    const nodeStream = Readable.fromWeb(upstream.body as never)
    nodeStream.on('error', () => res.end())
    nodeStream.pipe(res)
  } else {
    res.end()
  }
}

function attachConnectHandler(httpServer: Server): void {
  httpServer.on('connect', (req, socket: Socket, head) => {
    const target = req.url ?? ''
    const [hostRaw] = target.split(':')
    const host = hostRaw ?? ''
    if (!host || !knownRouters().includes(host)) {
      socket.end(
        `HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\n\r\nTinfoil tray does not proxy ${host}\r\n`
      )
      return
    }

    void leafContextFor(host)
      .then((ctx) => {
        if (!httpsHandler) {
          socket.end('HTTP/1.1 500 Internal Server Error\r\n\r\n')
          return
        }
        socket.write('HTTP/1.1 200 Connection Established\r\n\r\n', (err) => {
          if (err) {
            socket.destroy(err)
            return
          }
          if (head && head.length) socket.unshift(head)
          ;(socket as unknown as { _tinfoilHost?: string })._tinfoilHost = host
          ;(socket as unknown as { _tinfoilCtx?: unknown })._tinfoilCtx = ctx
          httpsHandler!.emit('connection', socket)
        })
      })
      .catch((err) => {
        socket.end(`HTTP/1.1 500 Internal Server Error\r\n\r\n${String(err)}`)
      })
  })
}

function createHttpsForwarder(): ReturnType<typeof createHttpsServer> {
  return createHttpsServer(
    {
      SNICallback: (servername, cb) => {
        leafContextFor(servername)
          .then((ctx) => cb(null, ctx))
          .catch((err) => cb(err as Error))
      }
    },
    (req, res) => {
      const sock = req.socket as unknown as { _tinfoilHost?: string }
      handle(req, res, sock?._tinfoilHost).catch((err) => {
        res.statusCode = 500
        res.end(String(err))
      })
    }
  )
}

async function tryListenOnPort(port: number): Promise<{ port: number; endpoint: string } | null> {
  const forwarder = createHttpsForwarder()
  const instance = createServer((req, res) => {
    handle(req, res).catch((err) => {
      res.statusCode = 500
      res.end(String(err))
    })
  })
  attachConnectHandler(instance)

  try {
    await new Promise<void>((resolve, reject) => {
      const onError = (err: NodeJS.ErrnoException) => {
        instance.off('error', onError)
        reject(err)
      }
      instance.once('error', onError)
      instance.listen(port, PROXY_LISTEN_HOST, () => {
        instance.off('error', onError)
        resolve()
      })
    })
  } catch (err) {
    forwarder.close()
    await new Promise<void>((resolve) => instance.close(() => resolve()))
    if ((err as NodeJS.ErrnoException).code === 'EADDRINUSE') {
      return null
    }
    throw err
  }

  server = instance
  httpsHandler = forwarder
  const address = instance.address()
  const boundPort = typeof address === 'object' && address ? address.port : port
  return { port: boundPort, endpoint: LOCAL_ENDPOINT_URL }
}

export async function startProxy(
  preferredPort: number
): Promise<{ port: number; endpoint: string } | null> {
  if (server) await stopProxy()

  const tried: number[] = []
  for (let offset = 0; offset < PROXY_PORT_MAX_ATTEMPTS; offset++) {
    const candidate = preferredPort + offset
    tried.push(candidate)
    const result = await tryListenOnPort(candidate)
    if (result) {
      stateStore.set({ port: result.port, endpoint: result.endpoint })
      return result
    }
  }

  const firstTried = tried[0] ?? preferredPort
  const lastTried = tried[tried.length - 1] ?? preferredPort
  stateStore.set({
    port: 0,
    endpoint: undefined,
    lastError: `Could not start local proxy: ports ${firstTried}-${lastTried} are all in use`
  })
  return null
}

export async function stopProxy(): Promise<void> {
  if (!server) return
  await new Promise<void>((resolve) => server!.close(() => resolve()))
  server = undefined
  if (httpsHandler) {
    httpsHandler.close()
    httpsHandler = undefined
  }
}

export function pacUrl(): string | undefined {
  const port = stateStore.get().port
  if (!port) return undefined
  return `http://${PROXY_LISTEN_HOST}:${port}/proxy.pac`
}
