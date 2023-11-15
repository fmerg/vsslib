# `vsslib.ies`

```js
const { ies, backend } = require('vsslib');

const ctx = backend.initGroup('ed25519');

const { secret, point: pub } = await ctx.generateKeypair();
```

```js
const message = Uint8Array.from(Buffer.from('destroy earth'));

const { ciphertext } = await ies.encrypt(ctx, message, pub, {
  mode: 'aes-256-cbc',
  algorithm : 'sha512',
});
```

```js
const plaintext = await ies.decrypt(ctx, ciphertext, secret);
```
