import { HKDF } from '@stablelib/hkdf'
import { SHA256, hash } from '@stablelib/sha256'
import type { bytes32, bytes } from '../@types/basic.js'
import type { Hkdf } from '../@types/handshake.js'
import type { KeyPair } from '../@types/libp2p.js'
import type { ICryptoInterface } from './crypto.js'
import sodium from 'libsodium-wrappers';
await sodium.ready;
import crypto from 'crypto';

const CHACHA_POLY1305 = 'chacha20-poly1305';
export const lib: ICryptoInterface = {
  hashSHA256 (data: Uint8Array): Uint8Array {
    return hash(data)
  },

  getHKDF (ck: bytes32, ikm: Uint8Array): Hkdf {
    const hkdf = new HKDF(SHA256, ikm, ck)
    const okmU8Array = hkdf.expand(96)
    const okm = okmU8Array

    const k1 = okm.subarray(0, 32)
    const k2 = okm.subarray(32, 64)
    const k3 = okm.subarray(64, 96)

    return [k1, k2, k3]
  },

  generateX25519KeyPair (): KeyPair {
    const keypair = sodium.crypto_box_keypair()

    return {
      publicKey: keypair.publicKey,
      privateKey: keypair.privateKey
    }
  },

  generateX25519KeyPairFromSeed (seed: Uint8Array): KeyPair {
    const keypair = sodium.crypto_box_seed_keypair(seed)

    return {
      publicKey: keypair.publicKey,
      privateKey: keypair.privateKey
    }
  },

  generateX25519SharedKey (privateKey: Uint8Array, publicKey: Uint8Array): Uint8Array {
    return sodium.crypto_box_beforenm(publicKey,privateKey)
  },

  chaCha20Poly1305Encrypt (plaintext: Uint8Array, nonce: Uint8Array, ad: Uint8Array, k: bytes32): bytes {
    const cipher = crypto.createCipheriv(CHACHA_POLY1305, k, nonce, {
      authTagLength: 16
    });
    cipher.setAAD(ad, {plaintextLength: plaintext.byteLength})
    const updated = cipher.update(plaintext);
    const final = cipher.final();
    const tag = cipher.getAuthTag();

   const encrypted = Buffer.concat([
        updated,
        tag,
        final,
    ]);
    return  encrypted;
  },

  chaCha20Poly1305Decrypt (ciphertext: Uint8Array, nonce: Uint8Array, ad: Uint8Array, k: bytes32, dst?: Uint8Array): bytes | null {

    const authTag = ciphertext.slice(ciphertext.length - 16)
    const text = ciphertext.slice(0,ciphertext.length - 16)
    let decipher = crypto.createDecipheriv(
      CHACHA_POLY1305,
      k,
      nonce,
      {
        authTagLength: 16
      }
    );
    decipher.setAAD(
      ad,
       {
        plaintextLength: text.byteLength
       }
    );
    decipher.setAuthTag(authTag)
    const updated = decipher.update(text);
    return updated
  }
}
