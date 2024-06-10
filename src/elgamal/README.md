# `vsslib.elgamal`

```js
import elgamal from 'vsslib/elgamal';

import { ElgamalSchemes, Algorithms, BlockModes } from 'vsslib/enums';
```

```js
import { backend } from 'vsslib';

const ctx = initGroup('ed25519');
```

```js
const { secret, publicBytes } = await ctx.generateSecret();
```

## Encryption schemes


### DHIES-ElGamal Encryption (Integrated Encryption Scheme)

```js
const cipher = elgamal(ctx, ElgamalSchemes.DHIES, BlockModes.AES_256_CBC, Algorithms.SHA256);
```

```js
const message = Buffer.from('destroy earth');

const { ciphertext, randomness, decryptor } = await cipher.encrypt(message, publicBytes);
```

### HYBRID-ElGamal Encryption (Key Encapsulation Mechanism)

```js
const cipher = elgamal(ctx, ElgamalSchemes.HYBRID, BlockModes.AES_256_CBC);
```

```js
const message = Buffer.from('destroy earth');

const { ciphertext, randomness, decryptor } = await cipher.encrypt(message, publicBytes);
```

### Plain ElGamal Encryption

```js
const cipher = elgamal(ctx, ElgamalSchemes.PLAIN);
```

```js
const message = (await ctx.randomPoint()).toBytes();
```

```js
const { ciphertext, randomness, decryptor } = await cipher.encrypt(message, publicBytes);
```

## Decryption methods

```js
const plaintext = await cipher.decrypt(ciphertext, secret);
```

```js
const plaintext = await cipher.decryptWithDecryptor(ciphertext, decryptor);
```

```js
const plaintext = await cipher.decryptWithRandomness(ciphertext, publicBytes, randomness);
```
