/* eslint-disable */
import benchmark from 'benchmark'
import  webcrypto  from 'crypto'
import { stablelib as crypto } from '../src/crypto/libsodium.js'
import { equals} from 'uint8arrays'
import sodium from 'libsodium-wrappers';
await sodium.ready;
const suite = new benchmark.Suite('crypto');
const rng =  webcrypto.randomBytes(1e6); // 1mb;
suite.add('chacha', () => {
  const key = webcrypto.randomBytes(32);
  const nonce =  webcrypto.randomBytes(12);
  const ad = webcrypto.randomBytes(32);
  const encrypted = crypto.chaCha20Poly1305Encrypt(rng,nonce,ad, key)
  const decrypted = crypto.chaCha20Poly1305Decrypt(encrypted,nonce,ad, key)!
  if(!equals(decrypted,rng))
  {
    throw new Error("Unexpected")
  }
}).on('error',(error: any)=>{
  console.error("ERROR", error)
}).on('cycle', function (stats: any) {
  console.log(String(stats.target))
}).run()

