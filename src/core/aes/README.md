# `vsslib.aes`

```js
import aes from 'vsslib/core/aes';
```

```js
const crypto = require('crypto');

const key = crypto.randomBytes(32);
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
