# `vsslib.crypto`

## Hash functions

```js
import { hash } from 'vsslib/crypto';

const digest = await hash(Algorithms.SHA256).digest(buffer);
```

## Hash-based Message Authentication (HMAC)

```js
import { hmac, randomBytes } from 'vsslib/crypto';

const key = randomBytes(32);
const digest = await hmac(Algorithms.SHA256, key).digest(buffer);
```

## Symmetric (AES) encryption

```js
import { aes, randomBytes } from 'vsslib/crypto';

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
