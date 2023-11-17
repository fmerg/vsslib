# `vsslib.elgamal`

```js
const { elgamal, backend } = require('vsslib');

const ctx = backend.initGroup('ed25519');
```

```js
const { secret, pub } = await ctx.generateKeypair();
```

```js
const message = await ctx.randomPoint();

const { ciphertext, randomness, decryptor } = await elgamal.encrypt(ctx, message, pub);
```

```js
const plaintext = await elgamal.decrypt(ctx, ciphertext, secret);
```

```js
const plaintext = await elgamal.decryptWithDecryptor(ctx, ciphertext, decryptor);
```

```js
const plaintext = await elgamal.decryptWithRandomness(ctx, ciphertext, pub, randomness);
```
