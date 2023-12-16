/* eslint-disable */
import crypto  from 'crypto'
import benchmark from 'benchmark'
import { equals} from 'uint8arrays'
import { defaultCrypto as libBrowser } from '../src/crypto/index.browser.js'
import { defaultCrypto as libNode } from '../src/crypto/index.js'

import sodium from 'libsodium-wrappers';
await sodium.ready; // we need to do this prior to the benchmark to load the wasm module

const suite = new benchmark.Suite('crypto');
const rng = crypto.randomBytes(1e6); // 1mb;

suite.add('browser', () => {
  const key =new Uint8Array( crypto.randomBytes(32))
  const nonce = new Uint8Array( crypto.randomBytes(12))
  const ad =new Uint8Array( crypto.randomBytes(32))
  const encrypted = libBrowser.chaCha20Poly1305Encrypt(rng,nonce,ad, key)
  const decrypted = libBrowser.chaCha20Poly1305Decrypt(encrypted,nonce,ad, key)!
  if(!equals(decrypted.subarray(),rng))
  {
    throw new Error("Unexpected")
  }
}) .add('native', () => {
  const key =new Uint8Array( crypto.randomBytes(32))
  const nonce = new Uint8Array( crypto.randomBytes(12))
  const ad =new Uint8Array( crypto.randomBytes(32))
  const encrypted = libNode.chaCha20Poly1305Encrypt(rng,nonce,ad, key)
  const decrypted = libNode.chaCha20Poly1305Decrypt(encrypted,nonce,ad, key)!
  if(!equals(decrypted.subarray(),rng))
  {
    throw new Error("Unexpected")
  }
}).on('error',(error: any)=>{
  console.error("ERROR", error)
}).on('cycle', function (stats: any) {
  console.log(String(stats.target))
}).run() 

