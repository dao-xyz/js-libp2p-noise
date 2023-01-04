import type { ConnectionEncrypter } from '@libp2p/interface-connection-encrypter'
import { Noise } from './noise.js'
import type { NoiseInit } from './noise.js'
import type { NoiseExtensions } from './proto/payload.js'
export * from './crypto/crypto.js'
export * from '#noise-crypto'

export function noise (init: NoiseInit = {}): () => ConnectionEncrypter<NoiseExtensions> {
  return () => new Noise(init)
}
