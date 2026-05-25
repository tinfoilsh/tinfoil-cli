import { ATC_BASE_URL, ATC_ROUTERS_PATH } from './constants.js'

export async function fetchRouters(): Promise<string[]> {
  const response = await fetch(`${ATC_BASE_URL}${ATC_ROUTERS_PATH}`)
  if (!response.ok) {
    throw new Error(`atc.tinfoil.sh/routers responded ${response.status}`)
  }
  const list = (await response.json()) as unknown
  if (!Array.isArray(list)) {
    throw new Error('atc.tinfoil.sh/routers returned a non-array response')
  }
  const routers = list.filter(
    (entry): entry is string => typeof entry === 'string' && entry.length > 0
  )
  if (routers.length === 0) {
    throw new Error('atc.tinfoil.sh/routers returned no usable router entries')
  }
  return routers
}

export function pickRandomRouter(routers: string[]): string {
  if (routers.length === 0) throw new Error('No routers available')
  const idx = Math.floor(Math.random() * routers.length)
  return routers[idx]!
}
