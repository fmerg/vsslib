# `vsslib.ies`

```js
const { ies, backend } = require('vsslib');

const ctx = backend.initGroup('ed25519');

const { secret, pub } = await ctx.generateKeypair();
```

```js
const message = Uint8Array.from(Buffer.from('destroy earth'));
const mode = 'aes-256-cbc';
const algorithm = 'sha512';

const { ciphertext } = await ies.encrypt(ctx, message, pub, { mode, algorithm });
```

```js
const plaintext = await ies.decrypt(ctx, ciphertext, secret);
```
