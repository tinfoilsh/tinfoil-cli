export const ATC_BASE_URL = 'https://atc.tinfoil.sh'
export const ATC_ROUTERS_PATH = '/routers?platform=snp'

export const VERIFICATION_CENTER_URL = 'https://verification-center.tinfoil.sh'

export const PROXY_DEFAULT_PORT = 8080
export const PROXY_LISTEN_HOST = '127.0.0.1'
export const PROXY_PORT_MAX_ATTEMPTS = 10

export const LOCAL_ENDPOINT_HOST = 'local.tinfoil.sh'
export const LOCAL_ENDPOINT_URL = 'https://local.tinfoil.sh/v1'

export const REVERIFY_INTERVAL_MS = 60_000
export const ROUTERS_REFRESH_INTERVAL_MS = 5 * 60_000

export const POPUP_WIDTH = 440
export const POPUP_HEIGHT_COMPACT = 140
export const POPUP_HEIGHT_COMPACT_MIN = 80
export const POPUP_HEIGHT_EXPANDED = 720

export const HOP_BY_HOP_HEADERS = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailers',
  'transfer-encoding',
  'upgrade',
  'host',
  'content-length'
])
