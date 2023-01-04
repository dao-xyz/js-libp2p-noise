/* eslint-disable */
import benchmark from 'benchmark'
import crypto  from 'crypto'
import { lib as libBrowser } from '../src/crypto-browser.js'
import { lib as libNode } from '../src/crypto-node.js'
import { equals} from 'uint8arrays'
import sodium from 'libsodium-wrappers';
await sodium.ready;
const suite = new benchmark.Suite('crypto');
const rng = crypto.randomBytes(1e6); // 1mb;
suite.add('browser', () => {
  const key = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(12);
  const ad = crypto.randomBytes(32);
  const encrypted = libBrowser.chaCha20Poly1305Encrypt(rng,nonce,ad, key)
  const decrypted = libBrowser.chaCha20Poly1305Decrypt(encrypted,nonce,ad, key)!
  if(!equals(decrypted,rng))
  {
    throw new Error("Unexpected")
  }
}).add('native', () => {
  const key = crypto.randomBytes(32);
  const nonce = crypto.randomBytes(12);
  const ad = crypto.randomBytes(32);
  const encrypted = libNode.chaCha20Poly1305Encrypt(rng,nonce,ad, key)
  const decrypted = libNode.chaCha20Poly1305Decrypt(encrypted,nonce,ad, key)!
  if(!equals(decrypted,rng))
  {
    throw new Error("Unexpected")
  }
}).on('error',(error: any)=>{
  console.error("ERROR", error)
}).on('cycle', function (stats: any) {
  console.log(String(stats.target))
}).run()

