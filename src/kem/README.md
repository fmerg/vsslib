# `vsslib.kem`

```js
const { kem, backend } = require('vsslib');

const ctx = backend.initGroup('ed25519');

const { secret, point: pub } = await ctx.generateKeypair();
```

```js
const message = Uint8Array.from(Buffer.from('destroy earth'));

const { ciphertext } = await kem.encrypt(ctx, message, pub, { mode: 'aes-256-cbc' });
```

```js
const plaintext = await kem.decrypt(ctx, ciphertext, secret);
```
