import { Uint8ArrayList } from 'uint8arraylist'
import { fromString as uint8ArrayFromString } from 'uint8arrays'
import { alloc as uint8ArrayAlloc } from 'uint8arrays/alloc'
import { equals as uint8ArrayEquals } from 'uint8arrays/equals'
import { Nonce } from '../nonce.js'
import type { bytes, bytes32 } from '../@types/basic.js'
import type { CipherState, MessageBuffer, SymmetricState } from '../@types/handshake.js'
import type { ICryptoInterface } from '../crypto.js'
import type { NoiseComponents } from '../index.js'
import type { Logger } from '@libp2p/interface'

export interface DecryptedResult {
  plaintext: Uint8ArrayList | Uint8Array
  valid: boolean
}

export interface SplitState {
  cs1: CipherState
  cs2: CipherState
}

export abstract class AbstractHandshake {
  public crypto: ICryptoInterface
  private readonly log: Logger

  constructor (components: NoiseComponents, crypto: ICryptoInterface) {
    this.log = components.logger.forComponent('libp2p:noise:abstract-handshake')
    this.crypto = crypto
  }

  public encryptWithAd (cs: CipherState, ad: Uint8Array, plaintext: Uint8Array | Uint8ArrayList): Uint8Array | Uint8ArrayList {
    const e = this.encrypt(cs.k, cs.n, ad, plaintext)
    cs.n.increment()

    return e
  }

  public decryptWithAd (cs: CipherState, ad: Uint8Array, ciphertext: Uint8Array | Uint8ArrayList, dst?: Uint8Array): DecryptedResult {
    const { plaintext, valid } = this.decrypt(cs.k, cs.n, ad, ciphertext, dst)
    if (valid) cs.n.increment()

    return { plaintext, valid }
  }

  // Cipher state related
  protected hasKey (cs: CipherState): boolean {
    return !this.isEmptyKey(cs.k)
  }

  protected createEmptyKey (): bytes32 {
    return uint8ArrayAlloc(32)
  }

  protected isEmptyKey (k: bytes32): boolean {
    const emptyKey = this.createEmptyKey()
    return uint8ArrayEquals(emptyKey, k)
  }

  protected encrypt (k: bytes32, n: Nonce, ad: Uint8Array, plaintext: Uint8Array | Uint8ArrayList): Uint8Array | Uint8ArrayList {
    n.assertValue()

    return this.crypto.chaCha20Poly1305Encrypt(plaintext, n.getBytes(), ad, k)
  }

  protected encryptAndHash (ss: SymmetricState, plaintext: bytes): Uint8Array | Uint8ArrayList {
    let ciphertext
    if (this.hasKey(ss.cs)) {
      ciphertext = this.encryptWithAd(ss.cs, ss.h, plaintext)
    } else {
      ciphertext = plaintext
    }

    this.mixHash(ss, ciphertext)
    return ciphertext
  }

  protected decrypt (k: bytes32, n: Nonce, ad: bytes, ciphertext: Uint8Array | Uint8ArrayList, dst?: Uint8Array): DecryptedResult {
    n.assertValue()

    const encryptedMessage = this.crypto.chaCha20Poly1305Decrypt(ciphertext, n.getBytes(), ad, k, dst)

    if (encryptedMessage) {
      return {
        plaintext: encryptedMessage,
        valid: true
      }
    } else {
      return {
        plaintext: uint8ArrayAlloc(0),
        valid: false
      }
    }
  }

  protected decryptAndHash (ss: SymmetricState, ciphertext: Uint8Array | Uint8ArrayList): DecryptedResult {
    let plaintext: Uint8Array | Uint8ArrayList
    let valid = true
    if (this.hasKey(ss.cs)) {
      ({ plaintext, valid } = this.decryptWithAd(ss.cs, ss.h, ciphertext))
    } else {
      plaintext = ciphertext
    }

    this.mixHash(ss, ciphertext)
    return { plaintext, valid }
  }

  protected dh (privateKey: bytes32, publicKey: Uint8Array | Uint8ArrayList): bytes32 {
    try {
      const derivedU8 = this.crypto.generateX25519SharedKey(privateKey, publicKey)

      if (derivedU8.length === 32) {
        return derivedU8
      }

      return derivedU8.subarray(0, 32)
    } catch (e) {
      const err = e as Error
      this.log.error('error deriving shared key', err)
      return uint8ArrayAlloc(32)
    }
  }

  protected mixHash (ss: SymmetricState, data: Uint8Array | Uint8ArrayList): void {
    ss.h = this.getHash(ss.h, data)
  }

  protected getHash (a: Uint8Array, b: Uint8Array | Uint8ArrayList): Uint8Array {
    const u = this.crypto.hashSHA256(new Uint8ArrayList(a, b))
    return u
  }

  protected mixKey (ss: SymmetricState, ikm: bytes32): void {
    const [ck, tempK] = this.crypto.getHKDF(ss.ck, ikm)
    ss.cs = this.initializeKey(tempK)
    ss.ck = ck
  }

  protected initializeKey (k: bytes32): CipherState {
    return { k, n: new Nonce() }
  }

  // Symmetric state related

  protected initializeSymmetric (protocolName: string): SymmetricState {
    const protocolNameBytes = uint8ArrayFromString(protocolName, 'utf-8')
    const h = this.hashProtocolName(protocolNameBytes)

    const ck = h
    const key = this.createEmptyKey()
    const cs: CipherState = this.initializeKey(key)

    return { cs, ck, h }
  }

  protected hashProtocolName (protocolName: Uint8Array): bytes32 {
    if (protocolName.length <= 32) {
      const h = uint8ArrayAlloc(32)
      h.set(protocolName)
      return h
    } else {
      return this.getHash(protocolName, uint8ArrayAlloc(0))
    }
  }

  protected split (ss: SymmetricState): SplitState {
    const [tempk1, tempk2] = this.crypto.getHKDF(ss.ck, uint8ArrayAlloc(0))
    const cs1 = this.initializeKey(tempk1)
    const cs2 = this.initializeKey(tempk2)

    return { cs1, cs2 }
  }

  protected writeMessageRegular (cs: CipherState, payload: bytes): MessageBuffer {
    const ciphertext = this.encryptWithAd(cs, uint8ArrayAlloc(0), payload)
    const ne = this.createEmptyKey()
    const ns = uint8ArrayAlloc(0)

    return { ne, ns, ciphertext }
  }

  protected readMessageRegular (cs: CipherState, message: MessageBuffer): DecryptedResult {
    return this.decryptWithAd(cs, uint8ArrayAlloc(0), message.ciphertext)
  }
}
