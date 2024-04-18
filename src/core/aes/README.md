# `vsslib.aes`

```js
import { aes } from 'vsslib';
```

```js
const crypto = require('crypto');

const key = crypto.randomBytes(32);
```

### AES-256-CBC

```js
const message = Uint8Array.from(Buffer.from('destroy earth'));

const { ciphered, iv } = aes.encrypt(key, message, { mode: 'aes-256-cbc'});
```

```js
const deciphered = aes.decrypt(key, ciphered, iv, { mode: 'aes-256-cbc'});
```

### AES-256-GCM

```js
const message = Uint8Array.from(Buffer.from('destroy earth'));

const { ciphered, iv, tag } = aes.encrypt(key, message, { mode: 'aes-256-gcm'});
```

```js
const deciphered = aes.decrypt(key, ciphered, iv, { mode: 'aes-256-gcm', tag });
```
