# `vsslib.crypto`

## Hash functions

## Hash-based Message Authentication (HMAC)

## Symmetric (AES) encryption

```js
import aes from 'vsslib/crypto/aes';
```

```js
const { randomBytes } = require('vsslib/crypto/random');

const key = randomBytes(32);
```

### AES-256-CBC

```js
const message = Uint8Array.from(Buffer.from('destroy earth'));

const { ciphered, iv } = aes('aes-256-cbc').encrypt(key, message);
```

```js
const deciphered = aes('aes-256-cbc').decrypt(key, ciphered, iv);
```

### AES-256-GCM

```js
const message = Uint8Array.from(Buffer.from('destroy earth'));

const { ciphered, iv, tag } = aes('aes-256-gcm').encrypt(key, message);
```

```js
const deciphered = aes('aes-256-gcm').decrypt(key, ciphered, iv, tag);
```
