# `vsslib.schnorr`

```js
import { backend } from 'vsslib';

const ctx = initGroup('ed25519');

const { secret, pub } = await ctx.generateKepair();
```

```js
import signer from 'vsslib/signer';

const sig = signer(ctx, SignatureSchemes.SCHNORR, Algorithms.SHA256);
```

```js
const message = Uint8Array.from(Buffer.from('destroy earth'));

const signature = await sig.signBytes(secret, message);
```

```js
await sig.verifyBytes(pub.toBytes(), message, signature);
```
