## `vsslib.elgamal`

```js
const { elgamal, backend } = require('vsslib');

const ctx = backend.initGroup('ed25519');

const { secret, point: pub } = await ctx.generateKeypair();
```

## Encryption and decryption

```js
const message = await ctx.randomPoint();

const { ciphertext, randomness, decryptor } = await elgamal.encrypt(ctx, message, pub);
```

### Decryption with secret key

```js
const plaintext = await elgamal.decrypt(ctx, ciphertext, { secret });
```

### Decryption with decryptor

```js
const plaintext = await elgamal.decrypt(ctx, ciphertext, { decryptor });
```

### Decryption with randomness

```js
const plaintext = await elgamal.decrypt(ctx, ciphertext, { pub, randomness });
```
