import { Algorithms, ElgamalSchemes } from 'vsslib/enums';
import { System } from 'vsslib/types';
import { initBackend, generateKey } from 'vsslib';
import { toCanonical } from 'vsslib/common';
import { randomNonce } from 'vsslib/crypto';
import { cartesian, removeItem } from '../utils';
import { resolveTestConfig } from '../environ';

let { systems, algorithms, signatureSchemes: sigSchemes, elgamalSchemes: encSchemes} = resolveTestConfig();

// Signcryption is only defined for HYBRID and DHIES ElGamal encryption
// schemes; avoid the case of empty encryption schemes in PLAIN is specified
// from the command line
encSchemes = removeItem(encSchemes, ElgamalSchemes.PLAIN).length == 0 ?
  [ElgamalSchemes.DHIES, ElgamalSchemes.HYBRID] :
  removeItem(encSchemes, ElgamalSchemes.PLAIN);


describe('Signcryption', () => {
  it.each(cartesian([systems, encSchemes, sigSchemes, algorithms]))(
    'success - without nonce - over %s/%s/%s/%s', async (system, encScheme, sigScheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey: alicePrivate, publicKey: alicePublic } = await generateKey(ctx);
    const { privateKey: bobPrivate, publicKey: bobPublic } = await generateKey(ctx);

    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, signature } = await alicePrivate.sigEncrypt(
      message, bobPublic, {
        encScheme,
        sigScheme,
        algorithm,
      }
    );
    const { message: plaintext } = await bobPrivate.sigDecrypt(
      ciphertext, signature, alicePublic, {
        encScheme,
        sigScheme,
        algorithm,
      }
    );
    expect(plaintext).toEqual(message);
  });
  it.each(cartesian([systems, encSchemes, sigSchemes, algorithms]))(
    'success - with nonce - over %s/%s/%s/%s', async (system, encScheme, sigScheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey: alicePrivate, publicKey: alicePublic } = await generateKey(ctx);
    const { privateKey: bobPrivate, publicKey: bobPublic } = await generateKey(ctx);

    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await randomNonce();
    const { ciphertext, signature } = await alicePrivate.sigEncrypt(
      message, bobPublic, {
        encScheme,
        sigScheme,
        algorithm,
        nonce,
      }
    );
    const { message: plaintext } = await bobPrivate.sigDecrypt(
      ciphertext, signature, alicePublic, {
        encScheme,
        sigScheme,
        algorithm,
        nonce,
      }
    );
    expect(plaintext).toEqual(message);
  });
  it.each(cartesian([systems, encSchemes, sigSchemes, algorithms]))(
    'failure - recipient substitution - over %s/%s/%s/%s', async (system, encScheme, sigScheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey: alicePrivate, publicKey: alicePublic } = await generateKey(ctx);
    const { privateKey: bobPrivate, publicKey: bobPublic } = await generateKey(ctx);
    const { privateKey: carolPrivate, publicKey: carolPublic } = await generateKey(ctx);

    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, signature } = await alicePrivate.sigEncrypt(
      message, bobPublic, {
        encScheme,
        sigScheme,
        algorithm,
      }
    );
    const { message: original, innerSignature } = await bobPrivate.sigDecrypt(
      ciphertext, signature, alicePublic, {
        encScheme,
        sigScheme,
        algorithm,
      }
    );

    // Bob substitutes recipient and outer signature
    const bobSignature = await bobPrivate.signMessage(
      toCanonical({ ciphertext, recipient: carolPublic.asBytes() }), {
        scheme: sigScheme,
        algorithm,
      }
    );
    expect(
      carolPrivate.sigDecrypt(
        ciphertext, bobSignature, alicePublic, {
          encScheme,
          sigScheme,
          algorithm,
        }
      )
    ).rejects.toThrow('Invalid outer signature')
  });
  it.each(cartesian([systems, encSchemes, sigSchemes, algorithms]))(
    'failure - inner signature substitution - over %s/%s/%s/%s', async (system, encScheme, sigScheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey: alicePrivate, publicKey: alicePublic } = await generateKey(ctx);
    const { privateKey: bobPrivate, publicKey: bobPublic } = await generateKey(ctx);
    const { privateKey: carolPrivate, publicKey: carolPublic } = await generateKey(ctx);

    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, signature } = await alicePrivate.sigEncrypt(
      message, bobPublic, {
        encScheme,
        sigScheme,
        algorithm,
      }
    );
    const { message: original, innerSignature } = await bobPrivate.sigDecrypt(
      ciphertext, signature, alicePublic, {
        encScheme,
        sigScheme,
        algorithm,
      }
    );

    // Bob substitutes message and inner signature
    const bobMessage = Uint8Array.from(Buffer.from('don\'t destroy earth'));
    const bobInnerSignature = await bobPrivate.signMessage(bobMessage, {
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
      carolPrivate.sigDecrypt(
        bobCiphertext, signature, alicePublic, {
          encScheme,
          sigScheme,
          algorithm,
        }
      )
    ).rejects.toThrow('Invalid outer signature')
  });
  it.each(cartesian([systems, encSchemes, sigSchemes, algorithms]))(
    'failure - missing nonce - over %s/%s/%s/%s', async (system, encScheme, sigScheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey: alicePrivate, publicKey: alicePublic } = await generateKey(ctx);
    const { privateKey: bobPrivate, publicKey: bobPublic } = await generateKey(ctx);

    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await randomNonce();
    const { ciphertext, signature } = await alicePrivate.sigEncrypt(
      message, bobPublic, {
        encScheme,
        sigScheme,
        algorithm,
        nonce,
      }
    );
    expect(
      bobPrivate.sigDecrypt(
        ciphertext, signature, alicePublic, {
          encScheme,
          sigScheme,
          algorithm,
        }
      )
    ).rejects.toThrow('Invalid outer signature');
  });
  it.each(cartesian([systems, encSchemes, sigSchemes, algorithms]))(
    'failure - forged nonce - over %s/%s/%s/%s', async (system, encScheme, sigScheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey: alicePrivate, publicKey: alicePublic } = await generateKey(ctx);
    const { privateKey: bobPrivate, publicKey: bobPublic } = await generateKey(ctx);

    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await randomNonce();
    const { ciphertext, signature } = await alicePrivate.sigEncrypt(
      message, bobPublic, {
        encScheme,
        sigScheme,
        algorithm,
        nonce,
      }
    );
    expect(
      bobPrivate.sigDecrypt(
        ciphertext, signature, alicePublic, {
          encScheme,
          sigScheme,
          algorithm,
          nonce: await randomNonce()
        }
      )
    ).rejects.toThrow('Invalid outer signature');
  });
  it.each(cartesian([systems, encSchemes, sigSchemes, algorithms]))(
    'failure - wrong algorithm - over %s/%s/%s/%s', async (system, encScheme, sigScheme, algorithm) => {
    const ctx = initBackend(system);
    const { privateKey: alicePrivate, publicKey: alicePublic } = await generateKey(ctx);
    const { privateKey: bobPrivate, publicKey: bobPublic } = await generateKey(ctx);

    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await randomNonce();
    const { ciphertext, signature } = await alicePrivate.sigEncrypt(
      message, bobPublic, {
        encScheme,
        sigScheme,
        algorithm,
        nonce,
      }
    );
    expect(
      bobPrivate.sigDecrypt(
        ciphertext, signature, alicePublic, {
          encScheme,
          sigScheme,
          algorithm: (algorithm == Algorithms.SHA256 || algorithm == undefined) ?
            Algorithms.SHA512 :
            Algorithms.SHA256,
          nonce,
        }
      )
    ).rejects.toThrow('Invalid outer signature');
  });
});
