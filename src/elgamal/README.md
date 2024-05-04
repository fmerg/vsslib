# `vsslib.elgamal`

```js
import elgamal from 'vsslib/elgamal';

import { ElgamalSchemes, Algorithms, AesModes } from 'vsslib/enums';
```

```js
import { backend } from 'vsslib';

const ctx = initGroup('ed25519');
```

```js
const { secret, pub } = await ctx.generateKeypair();

const pubBytes = pub.toBytes();
```

## Encryption schemes


### IES-ElGamal Encryption (Integrated Encryption Scheme)

```js
const cipher = elgamal(ctx, ElgamalSchemes.IES, AesModes.AES_256_CBC, Algorithms.SHA256);
```

```js
const message = Buffer.from('destroy earth');

const { ciphertext, randomness, decryptor } = await cipher.encrypt(message, pubBytes);
```

### KEM-ElGamal Encryption (Key Encapsulation Mechanism)

```js
const cipher = elgamal(ctx, ElgamalSchemes.KEM, AesModes.AES_256_CBC);
```

```js
const message = Buffer.from('destroy earth');

const { ciphertext, randomness, decryptor } = await cipher.encrypt(message, pubBytes);
```

### Plain ElGamal Encryption

```js
const cipher = elgamal(ctx, ElgamalSchemes.PLAIN);
```

```js
const message = (await ctx.randomPoint()).toBytes();
```

```js
const { ciphertext, randomness, decryptor } = await cipher.encrypt(message, pubBytes);
```

## Decryption methods

```js
const plaintext = await cipher.decrypt(ciphertext, secret);
```

```js
const plaintext = await cipher.decryptWithDecryptor(ciphertext, decryptor);
```

```js
const plaintext = await cipher.decryptWithRandomness(ciphertext, pubBytes, randomness);
```
