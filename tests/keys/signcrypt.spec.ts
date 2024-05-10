import { Algorithms, ElgamalSchemes, SignatureSchemes } from '../../src/enums';
import { System } from '../../src/types';
import { Algorithm } from '../../src/types';
import { generateKey } from '../../src';
import { toCanonical } from '../../src/keys';
import { randomBytes } from '../../src/crypto';
import { cartesian, removeItem } from '../helpers';
import { resolveTestConfig } from '../environ';

let {
  systems,
  algorithms,
  signatureSchemes: sigSchemes,
  elgamalSchemes: encSchemes,
} = resolveTestConfig();

algorithms  = [...algorithms, undefined];

// Signcryption is only defined for KEM and IES ElGamal encryption schemes
encSchemes = removeItem(encSchemes, ElgamalSchemes.PLAIN);


describe('Signcryption - success without nonce', () => {
  it.each(cartesian([systems, encSchemes, sigSchemes, algorithms]))('over %s/%s/%s/%s', async (
    system, encScheme, sigScheme, algorithm
  ) => {
    const { privateKey: alicePrivate, publicKey: alicePublic } = await generateKey(system);
    const { privateKey: bobPrivate, publicKey: bobPublic } = await generateKey(system);

    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, signature } = await alicePrivate.signEncrypt(
      message, bobPublic, {
        encScheme,
        sigScheme,
        algorithm,
      }
    );
    const { message: plaintext } = await bobPrivate.verifyDecrypt(
      ciphertext, signature, alicePublic, {
        encScheme,
        sigScheme,
        algorithm,
      }
    );
    expect(plaintext).toEqual(message);
  });
});

describe('Signcryption - failure receiver substitution', () => {
  it.each(cartesian([systems, encSchemes, sigSchemes, algorithms]))('over %s/%s/%s/%s', async (
    system, encScheme, sigScheme, algorithm
  ) => {
    const { privateKey: alicePrivate, publicKey: alicePublic } = await generateKey(system);
    const { privateKey: bobPrivate, publicKey: bobPublic } = await generateKey(system);
    const { privateKey: carolPrivate, publicKey: carolPublic } = await generateKey(system);

    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, signature } = await alicePrivate.signEncrypt(
      message, bobPublic, {
        encScheme,
        sigScheme,
        algorithm,
      }
    );
    const { message: original, innerSignature } = await bobPrivate.verifyDecrypt(
      ciphertext, signature, alicePublic, {
        encScheme,
        sigScheme,
        algorithm,
      }
    );

    // Bob substitutes receiver and outer signature
    const bobSignature = await bobPrivate.sign(
      toCanonical({ ciphertext, receiver: carolPublic.bytes }), {
        scheme: sigScheme,
        algorithm,
      }
    );
    expect(
      carolPrivate.verifyDecrypt(
        ciphertext, bobSignature, alicePublic, {
          encScheme,
          sigScheme,
          algorithm,
        }
      )
    ).rejects.toThrow('Invalid signature')
  });
});

describe('Signcryption - failure; message and inner signature substitution', () => {
  it.each(cartesian([systems, encSchemes, sigSchemes, algorithms]))('over %s/%s/%s/%s', async (
    system, encScheme, sigScheme, algorithm
  ) => {
    const { privateKey: alicePrivate, publicKey: alicePublic } = await generateKey(system);
    const { privateKey: bobPrivate, publicKey: bobPublic } = await generateKey(system);
    const { privateKey: carolPrivate, publicKey: carolPublic } = await generateKey(system);

    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, signature } = await alicePrivate.signEncrypt(
      message, bobPublic, {
        encScheme,
        sigScheme,
        algorithm,
      }
    );
    const { message: original, innerSignature } = await bobPrivate.verifyDecrypt(
      ciphertext, signature, alicePublic, {
        encScheme,
        sigScheme,
        algorithm,
      }
    );

    // Bob substitutes message and inner signature
    const bobMessage = Uint8Array.from(Buffer.from('don\'t destroy earth'));
    const bobInnerSignature = await bobPrivate.sign(bobMessage, {
      scheme: sigScheme,
      algorithm
    });
    const { ciphertext: bobCiphertext } = await carolPublic.encrypt(
      toCanonical({ message: bobMessage, innerSignature: bobInnerSignature }), {
        scheme: encScheme,
        algorithm
      }
    );
    expect(
      carolPrivate.verifyDecrypt(
        bobCiphertext, signature, alicePublic, {
          encScheme,
          sigScheme,
          algorithm,
        }
      )
    ).rejects.toThrow('Invalid signature')
  });
});

describe('Signcryption - success with nonce', () => {
  it.each(cartesian([systems, encSchemes, sigSchemes, algorithms]))('over %s/%s/%s/%s', async (
    system, encScheme, sigScheme, algorithm
  ) => {
    const { privateKey: alicePrivate, publicKey: alicePublic } = await generateKey(system);
    const { privateKey: bobPrivate, publicKey: bobPublic } = await generateKey(system);

    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await randomBytes(16);
    const { ciphertext, signature } = await alicePrivate.signEncrypt(
      message, bobPublic, {
        encScheme,
        sigScheme,
        algorithm,
        nonce,
      }
    );
    const { message: plaintext } = await bobPrivate.verifyDecrypt(
      ciphertext, signature, alicePublic, {
        encScheme,
        sigScheme,
        algorithm,
        nonce,
      }
    );
    expect(plaintext).toEqual(message);
  });
});

describe('Signcryption - failure missing nonce', () => {
  it.each(cartesian([systems, encSchemes, sigSchemes, algorithms]))('over %s/%s/%s/%s', async (
    system, encScheme, sigScheme, algorithm
  ) => {
    const { privateKey: alicePrivate, publicKey: alicePublic } = await generateKey(system);
    const { privateKey: bobPrivate, publicKey: bobPublic } = await generateKey(system);

    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await randomBytes(16);
    const { ciphertext, signature } = await alicePrivate.signEncrypt(
      message, bobPublic, {
        encScheme,
        sigScheme,
        algorithm,
        nonce,
      }
    );
    expect(
      bobPrivate.verifyDecrypt(
        ciphertext, signature, alicePublic, {
          encScheme,
          sigScheme,
          algorithm,
        }
      )
    ).rejects.toThrow('Invalid signature');
  });
});

describe('Signcryption - failure forged nonce', () => {
  it.each(cartesian([systems, encSchemes, sigSchemes, algorithms]))('over %s/%s/%s/%s', async (
    system, encScheme, sigScheme, algorithm
  ) => {
    const { privateKey: alicePrivate, publicKey: alicePublic } = await generateKey(system);
    const { privateKey: bobPrivate, publicKey: bobPublic } = await generateKey(system);

    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await randomBytes(16);
    const { ciphertext, signature } = await alicePrivate.signEncrypt(
      message, bobPublic, {
        encScheme,
        sigScheme,
        algorithm,
        nonce,
      }
    );
    expect(
      bobPrivate.verifyDecrypt(
        ciphertext, signature, alicePublic, {
          encScheme,
          sigScheme,
          algorithm,
          nonce: await randomBytes(16)
        }
      )
    ).rejects.toThrow('Invalid signature');
  });
});

describe('Signcryption - failure wrong algorithm', () => {
  it.each(cartesian([systems, encSchemes, sigSchemes, algorithms]))('over %s/%s/%s/%s', async (
    system, encScheme, sigScheme, algorithm
  ) => {
    const { privateKey: alicePrivate, publicKey: alicePublic } = await generateKey(system);
    const { privateKey: bobPrivate, publicKey: bobPublic } = await generateKey(system);

    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await randomBytes(16);
    const { ciphertext, signature } = await alicePrivate.signEncrypt(
      message, bobPublic, {
        encScheme,
        sigScheme,
        algorithm,
        nonce,
      }
    );
    expect(
      bobPrivate.verifyDecrypt(
        ciphertext, signature, alicePublic, {
          encScheme,
          sigScheme,
          algorithm: (algorithm == Algorithms.SHA256 || algorithm == undefined) ?
            Algorithms.SHA512 :
            Algorithms.SHA256,
          nonce,
        }
      )
    ).rejects.toThrow('Invalid signature');
  });
});
