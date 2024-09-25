# `vsslib.keys`

High-level interface for discrete-log based public-key cryptography

:warning: **This is part of [`vsslib`](../..) and as such requires security audit.
Use at your own risk for the moment**

## Table of contents

* [Generation](#key-generation)
  * [Serialization](#serialization)
* [Schnorr identification](#schnorr-identification)
* [Elgamal encryption](#elgamal-encryption)
  * [Encryption](#encryption)
    * [DHIES-encryption (DH-based Integrated Encryption Scheme)](#dhies-encryption)
    * [Hybrid encryption ("Key Encapsulation Mechanism")](#hybrid-encryption)
    * [Plain encryption](#plain-encryption)
  * [Decryption](#decryption)
  * [Encryption with proof](#encryption-with-proof)
    * [Standalone proof of randomness](#standalone-proof-of-randomness)
* [Decryptors](#decryptors)
  * [Standalone proof-of-decryptor](#standalone-proof-of-decryptor)
* [Signatures](#signatures)
  * [Signcryption](#signcryption)
* [Key sharing]("#key-sharing")
  * [Feldman VSS Scheme](#feldman-scheme)
  * [Pedersen VSS Scheme](#pedersen-scheme)
  * [Public key recovery](#public-key-recovery)
* [Partial decryptors](#partial-decryptors)
  * [Partial decryptor generation](#partial-decryptor-generation)
  * [Decryptor recovery](#decryptor-recovery)
  * [Recovery with accurate blaming](#recovery-with-accurate-blaming)
  * [Raw combination of partial decryptors](#raw-combination-of-partial-decryptors)

## Generation

```js
import { initBackend, generateKey } from "vsslib";

// Initiate cryptosystem over the ED25519 elliptic curve
const ctx = initBackend("ed25519");

// Generate keypair over the fixed cryptosystem instance
const { privateKey, publicKey } = await generateKey(ctx);
```

Alternatively, extract the public counterpart as follows:

```js
// Generate key over the fixed cryptosystem instance
const { privateKey } = await generateKey(ctx);

// Extract public counterpart from key
const publicKey = await privateKey.getPublicKey();
```

### Serialization

Derive the byte representation of a public key as follows.

```js
const publicBytes = await publicKey.asBytes();  // uint8 array
```

Retrieve the public key instance from its byte representation as follows.

```js
const receivedPublic = new PublicKey(ctx, publicBytes);
```

## <a name="schnorr-identification"></a>Schnorr identification (NIZK proof of secret)

### Prover's side

Generate a NIZK (Schnorr) proof-of-knowledge of the key's secret value as
follows.

```js
const proof = await privateKey.proveSecret({ algorithm: "sha256", nonce: ... });
```

The optional `algorithm` parameter specifies the hash function used for the
Fiat-Shamir transform (defaults to SHA256). The optional `nonce` parameter is
any bytestring maintaining state between prover and verifier, so that the
latter defends themselves against replay attacks.

### Verifier's side

Verify the proof against respective public key as follows:

```js
await publicKey.verifySecret(proof, { algorithm: "sha256", nonce: ... });
```

This throws `InvalidSecret` error in case of verification failure,
which you will usually have to handle:

```js
import { InvalidSecret } from "vsslib";

try {
  await publicKey.verifySecret(proof, { algorithm: ..., nonce: ... });
  ...
} catch (err) {
  if (err instanceof InvalidSecret) {
    // Follow policy as specified by context
    ...
  } else {
    ...
  }
}
```

## Elgamal encryption

Elgamal encryption schemes differ on how the decryptor is "encapsulated" under the hood
in order to "translate" the original message to the final ciphertext, i.e., by means of
raw group operation (as in plain encryption) or by means of some AES operation,
where an ephemeral symmetric key is produced.

### Encryption

The key API exposes a uniform encryption interface which abstracts away the encapsulation details.

```js
const { ciphertext, randomness, decryptor } = await publicKey.encrypt(message, { scheme: ..., ... });
```

The obligatory `scheme` parameter specifies the desired encryption scheme (see
below for the available options), which moreover specifies the acceptable
format of `message`. The rest parameters are optional and relate to the
selected scheme.

`ciphertext` refers to the main output of the encryption operation.
`randomness` is the random scalar generated during the process, which
admits further processing in some protocols and can be used to prove that the
operation was not bogus. The `decryptor` can be employed in
protocols where decruption is delegated to third parties
(see Sec. [Decryptors]("#decryptors") for details).

> **Warning** Both `randomness` and `decryptor` can be used to
> retrieve the original message without knowledge of the recipient's private
> key. If not immediately discarded, make sure that they do not leak.

The encryption operation may not complete if the provided message is not well
formatted with respect to the specified scheme. You may want to handle
separately the respective error as follows.

```js
import { ElgamalError } from "vsslib";

try {
  const { ciphertext, ... } = await publicKey.encrypt(message, { scheme: ..., ... });
  ...
} catch (err) {
  if (err instanceof ElgamalError) {
    // Handle encryption error
    ...
  } else {
    ...
  }
}
```


#### <a name="dhies-encryption"></a>DHIES-Encryption (DH-based Integrated Encryption Scheme)

In this case, `message` can be any bytestring.


```js
const message = Uint8Array.from(Buffer.from("destroy earth"));

const { ciphertext, ... } = await publicKey.encrypt(message, { scheme: "dhies", algorithm: "sha256", mode: "aes-256-cbc" });
```

The optional `algorithm` parameter specifies the hash function used to generate
the attached MAC (defaults to SHA256).
The optional `mode` parameter specified the AES block mode for the involved
symmetric operation (defaults to AES-256-CBC).


#### <a name="hybrid-encryption"></a>Hybrid encryption ("Key Encapsulation Mechanism")

In this case, `message` can be any bytestring.


```js
const message = Uint8Array.from(Buffer.from("destroy earth"));

const { ciphertext, ... } = await publicKey.encrypt(message, { scheme: "hybrid", mode: "aes-256-cbc" });
```

The optional `mode` parameter specified the AES block mode for the involved
symmetric operation (defaults to AES-256-CBC).

#### <a name="plain-encryption"></a>Plain encryption

In this case, `message` must be the byte representation of a group element.

```js
const message = await randomPublic(ctx);

const { ciphertext, ... } = await publicKey.encrypt(message, { scheme: "plain" });
```

No optional parameters apply for this scheme.

> **Warning**: Plain encryption is semantically but not CCA secure.
> Make sure that it is securely employed in context by other means.

### Decryption

The decryption interface is uniform for all encryption schemes
(see Sec. [Elgamal encryption](#elgamal-encryption)).

Given a ciphertext generated in any of the above ways, use the respective private key to
decrypt it as follows.

```js
const plaintext = privateKey.decrypt(ciphertext, { scheme: ..., ... });
```

The obligatory `scheme` parameter specifies the expected encryption scheme and
should coincide with that used during ciphertext generation.
The rest parameters are optional and should
coincide with those applied during ciphertext generation.

#### Decryption failure

Depending on scheme, the decryption operation may fail to complete throwing
`ElgamalError` (e.g., if the included MAC is found invalid in case of DHIES decryption).
You may need to handle this error separately.

```js
import { ElgamalError } from "vsslib";

try {
  const plaintext = privateKey.decrypt(ciphertext, { scheme: ..., ... })
  ...
} catch (err) {
  if (err instanceof ElgamalError) {
    // Handle decryption error
    ...
  } else {
    ...
  }
}
```

### <a name="encryption-with-proof"></a>Encryption with proof

```js
const { ciphertext, proof } = await publicKey.encryptProve(message, { scheme: "dhies" })
```

```js
const { plaintext } = await privateKey.verifyDecrypt(ciphertext, proof, { scheme: "dhies" })
```

### Standalone proof of randomness

```js
const proof = await publicKey.proveEncryption(ciphertext, randomness, { algorithm: "sha256" });
```

```js
await privateKey.verifyEncryption(ciphertext, proof, { algorithm: "sha256" });
```

## Decryptors

```js
const { decryptor, proof } = await privateKey.computeDecryptor(ciphertext, { algorithm: "sha256" });
```

```js
await publicKey.verifyDecryptor(ciphertext, decryptor, proof, { algorithm: "sha256" });
```

### <a name="standalone-proof-of-decryptor"></a>Standalone proof-of-decryptor


```js
const proof = await privateKey.proveDecryptor(ciphertext, decryptor, { algorithm: "sha256" })
```

## Signatures

```js
const message = Uint8Array.from(Buffer.from("destroy earth"));
```

```js
const signature = await privateKey.signMessage(message, { scheme: "schnorr", algorithm: "sha256" });
```

```js
await publicKey.verifySignature(message, signature, { scheme: "schnorr", algorithm: "sha256" });
```

### Signcryption

```js
const message = Uint8Array.from(Buffer.from("destroy earth"));
```

```js
const { ciphertext, signature } = await senderPrivate.sigEncrypt(message, recipientPublic, { encScheme: "hybrid", sigScheme: "schnorr" });
```

```js
const { plaintext } = await recipientPrivate.sigDecrypt(ciphertext, signature, senderPublic, { encScheme: "hybrid", sigScheme: "schnorr" });
```

## Key sharing

```js
const { privateKey } = await generateKey(ctx);

const sharing = await privateKey.generateSharing(5, 3);
```

### <a name="feldman-scheme"></a>Feldman VSS Scheme

```js
const { packets, commitments } = await sharing.createFeldmanPackets();
```

```js
import { extractPartialKey } from "vsslib";

const privateShare = await extractPartialKey(ctx, commitments, packet);
```

### <a name="pedersen-scheme"></a>Pedersen VSS Scheme

```js
const { packets, commitments } = await sharing.createPedersenPackets(publicBytes);
```

```js
import { extractPartialKey } from "vsslib";

const privateShare = await extractPartialKey(ctx, commitments, packet);
```

### <a name="public-key-recovery"></a>Public key recovery

```js
import { recoverPublicKey } from "vsslib";
```

```js
const { publicKey } = await recoverPublicKey(ctx, publicKeyShares, { algorithm });
```

```js
const { publicKey, blame } = await recoverPublicKey(ctx, publicKeyShares, { algorithm, errorOnInvalid: false });
```

## <a name="partial-decryptors"></a>Partial decryptors

### <a name="partial-decryptor-generation"></a>Partial decryptor generation

### <a name="decryptor-recovery"></a>Decryptor recovery

### <a name="recovery-accurate-blaming"></a>Recovery with accurate blaming

### <a name="raw-combination-of-partial-decryptors"></a>Raw combination of partial decryptors
