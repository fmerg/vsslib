## `vsslib.utils`

```js
const { utils } = require('vsslib');
```

### Bitwise

```js
// Little-endian to bigInt
const number = utils.leBuff2Int(new Uint8Array[1, 2, 3, 255]);  // 4278387201n

// bigInt to little-endian
const buffer = utils.leInt2Buff(4278387201n); // Uint8Array(4) [1, 2, 3, 255]
```

### Arith

```js
// 9 modulo 7
const a = utils.mod(BigInt(9), BigInt(12));           // 5n

// -9 modulo 7
const b = utils.mod(BigInt(-9), BigInt(12));          // 3n

// Inverse of 5 modulo 9
const c = utils.modInv(BigInt(5), BigInt(9));         // 2n

// Greatest common divisor of 8 and 12
const d = utils.gcd(BigInt(8), BigInt(12));           // 4n
```

