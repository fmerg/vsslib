## `vsslib.utils`

```js
const utils = require('vsslib/utils');
```

### Hashing

```js
const textBytes = Buffer.from('some text');

// Digest as bytes
const digest = utils.hash(textBytes, { algorithm: 'sha256' });

// Digest as string
const hexDigest = utils.hash(textBytes, { algorithm: 'sha256', encoding: 'hex' });
const b64Digest = utils.hash(textBytes, { algorithm: 'sha256', encoding: 'base64' });
```

### Random

```js
const num = await utils.randomInteger(64);
```

### Bitwise

```js
// Little-endian to bigInt
const number = utils.leBuff2Int(new Uint8Array[1, 2, 3, 255]);  // 4278387201n

// bigInt to little-endian
const buffer = utils.leInt2Buff(4278387201n); // Uint8Array(4) [1, 2, 3, 255]
```
