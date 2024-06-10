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

## Symmetric encryption (AES)

```js
import { aes, randomBytes } from 'vsslib/crypto';

const key = randomBytes(32);
```

### AES-256-[CBC|CFB|OFB|CTR]

```js
const message = Uint8Array.from(Buffer.from('destroy earth'));

const { ciphered, iv } = aes(BlockModes.AES_256_CBC).encrypt(key, message);
```

```js
const deciphered = aes(BlockModes.AES_256_CBC).decrypt(key, ciphered, iv);
```

### AES-256-GCM

```js
const message = Uint8Array.from(Buffer.from('destroy earth'));

const { ciphered, iv, tag } = aes(BlockModes.AES_256_GCM).encrypt(key, message);
```

```js
const deciphered = aes(BlockModes.AES_256_GCM).decrypt(key, ciphered, iv, tag);
```
