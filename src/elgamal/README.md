# `vsslib.elgamal`

```js
import { backend } from 'vsslib';

const ctx = backend.initGroup('ed25519');
```

```js
const { secret, pub } = await ctx.generateKeypair();
```

## Plain plain Encryption

```js
import { plain } from 'vsslib';
```

```js
const message = await ctx.randomPoint();

const { ciphertext, randomness, decryptor } = await plain(ctx).encrypt(message, pub);
```

```js
const plaintext = await plain(ctx).decrypt(ciphertext, secret);
```

```js
const plaintext = await plain(ctx).decryptWithDecryptor(ciphertext, decryptor);
```

```js
const plaintext = await plain(ctx).decryptWithRandomness(ciphertext, pub, randomness);
```

## (DH)KEM-Encryption (Key Encapsulation Mechanism)

```js
import { kem } from 'vsslib';
```

```js
const message = await ctx.randomPoint();

const { ciphertext, randomness, decryptor } = await kem(ctx, { mode: 'aes-256-cbc' }).encrypt(message, pub);
```

```js
const plaintext = await kem(ctx).decrypt(ciphertext, secret);
```

```js
const plaintext = await kem(ctx).decryptWithDecryptor(ciphertext, decryptor);
```

```js
const plaintext = await kem(ctx).decryptWithRandomness(ciphertext, pub, randomness);
```


## (DH/EC)IES-Encryption (Integrated Encryption Scheme)

```js
import { ies } from 'vsslib';
```

```js
const message = await ctx.randomPoint();

const { ciphertext, randomness, decryptor } = await ies(ctx, { mode, algorithm }).encrypt(message, pub);
```

```js
const plaintext = await ies(ctx).decrypt(ciphertext, secret);
```

```js
const plaintext = await ies(ctx).decryptWithDecryptor(ciphertext, decryptor);
```

```js
const plaintext = await ies(ctx).decryptWithRandomness(ciphertext, pub, randomness);
```
