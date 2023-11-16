# `vsslib.asymmetric`

```js
import { backend } from 'vsslib';

const ctx = backend.initGroup('ed25519');
```

```js
const { secret, pub } = await ctx.generateKeypair();
```

## Plain ElGamal Encryption

```js
import { elgamal } from 'vsslib';
```

```js
const message = await ctx.randomPoint();

const { ciphertext, randomness, decryptor } = await elgamal(ctx).encrypt(message, pub);
```

```js
const plaintext = await elgamal(ctx).decrypt(ciphertext, secret);
```

```js
const plaintext = await elgamal(ctx).decryptWithDecryptor(ciphertext, decryptor);
```

```js
const plaintext = await elgamal(ctx).decryptWithRandomness(ciphertext, pub, randomness);
```

## DHKEM-hybrid Encryption (Key Encapsulation Mechanism)

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


## (DH/EC)IES-hybrid Encryption (Integrated Encryption Scheme)

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