# js-libp2p-noise
## This is a fork for [ChainSafe/js-libp2p-noise](https://github.com/ChainSafe/js-libp2p-noise) where performance gains are made by utilising [libsodium.js](https://www.npmjs.com/package/libsodium-wrappers) (appx. 20-50% gain) instead of 'stablelib' for browser usages, and Node crypto native lib from Node apps (500-700% gain).

This fork is ESM only.

![npm](https://img.shields.io/npm/v/@dao-xyz/libp2p-noise)
[![](https://img.shields.io/badge/project-libp2p-yellow.svg?style=flat-square)](https://libp2p.io/)
![](https://img.shields.io/github/issues-raw/dao-xyz/js-libp2p-noise)
![](https://img.shields.io/github/license/dao-xyz/js-libp2p-noise)
![](https://img.shields.io/badge/yarn-%3E%3D1.17.0-orange.svg?style=flat-square)
![](https://img.shields.io/badge/Node.js-%3E%3D16.0.0-orange.svg?style=flat-square)
![](https://img.shields.io/badge/browsers-last%202%20versions%2C%20not%20ie%20%3C%3D11-orange)
[![Discourse posts](https://img.shields.io/discourse/https/discuss.libp2p.io/posts.svg)](https://discuss.libp2p.io)
dao-xyz
> Noise libp2p handshake for js-libp2p

This repository contains TypeScript implementation of noise protocol, an encryption protocol used in libp2p.

##### Warning: Even though this package works in browser, it will bundle around 600Kb (200Kb gzipped) of code
https://bundlephobia.com/result?p=@dao-xyz/libp2p-noise@latest

## Usage

Install with `yarn add @dao-xyz/libp2p-noise` or `npm i @dao-xyz/libp2p-noise`.

Example of using default noise configuration and passing it to the libp2p config:

```js
import {noise} from "@dao-xyz/libp2p-noise"

//custom noise configuration, pass it instead of `new Noise()`
//x25519 private key
const n = noise(privateKey);

const libp2p = new Libp2p({
   modules: {
     connEncryption: [noise()],
   },
});
```

Where parameters for Noise constructor are:
 - *static Noise key* - (optional) existing private Noise static key
 - *early data* - (optional) an early data payload to be sent in handshake messages



## API

This module exposes a crypto interface, as defined in the repository [js-interfaces](https://github.com/libp2p/js-libp2p-interfaces).

[» API Docs](https://github.com/libp2p/js-libp2p-interfaces/tree/master/packages/interface-connection-encrypter#api)

## Bring your own crypto

You can provide a custom crypto implementation (instead of the default, based on [stablelib](https://www.stablelib.com/)) by passing a third argument to the `Noise` constructor.

The implementation must conform to the `ICryptoInterface`, defined in https://github.com/dao-xyz/js-libp2p-noise/blob/master/src/crypto/crypto.ts

## Contribute

Feel free to join in. All welcome. Open an issue!

[![](https://cdn.rawgit.com/jbenet/contribute-ipfs-gif/master/img/contribute.gif)](https://github.com/ipfs/community/blob/master/contributing.md)

## License

Licensed under either of

 * Apache 2.0, ([LICENSE-APACHE](LICENSE-APACHE) / http://www.apache.org/licenses/LICENSE-2.0)
 * MIT ([LICENSE-MIT](LICENSE-MIT) / http://opensource.org/licenses/MIT)