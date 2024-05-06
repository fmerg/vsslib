# `vsslib.schnorr`

```js
import { backend, signer } from 'vsslib';

const ctx = initGroup('ed25519');

const { secret, pub } = await ctx.generateKepair();
```

```js
const message = Uint8Array.from(Buffer.from('destroy earth'));

const signature = await signer(ctx, SignatureSchemes.SCHNORR, Algorithms.SHA256).signBytes(
  secret, message
);
```

```js
const verified = await signer(ctx, SignatureSchemes.SCHNORR, Algorithms.SHA256).verifyBytes(
  pub, message, signature
);
```
