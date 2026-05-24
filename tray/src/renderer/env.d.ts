import type { TinfoilApi } from '../preload'

declare global {
  interface Window {
    tinfoil: TinfoilApi
  }
}

export {}
