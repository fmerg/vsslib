# `vsslib.schnorr`

```js
import { schnorr, backend } from 'vsslib';

const ctx = backend.initGroup('ed25519');

const { secret, pub } = await ctx.generateKepair();
```

```js
const message = Uint8Array.from(Buffer.from('destroy earth'));

const signature = await schnorr(ctx, algorithm).signBytes(secret, message);
```

```js
const verified = await schnorr(ctx).verifyBytes(pub, message, signature);
```
