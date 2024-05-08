import { Algorithms, ElgamalSchemes, SignatureSchemes } from '../../src/enums';
import { System } from '../../src/types';
import { Algorithm } from '../../src/types';
import { generateKey } from '../../src';
import { randomBytes } from '../../src/crypto/random';
import { cartesian, removeItem } from '../helpers';
import { resolveTestConfig } from '../environ';

let {
  systems,
  algorithms,
  signatureSchemes: sigSchemes,
  elgamalSchemes: encSchemes,
} = resolveTestConfig();

// algorithms  = [...algorithms, undefined];

// Signcryption is only defined for KEM and IES ElGamal encryption schemes
encSchemes = removeItem(encSchemes, ElgamalSchemes.PLAIN);

const setupKeys = async (system: System) => {
  const { privateKey: senderPrivate, publicKey: senderPublic } = await generateKey(system);
  const { privateKey: receiverPrivate, publicKey: receiverPublic } = await generateKey(system);
  return {
    senderPrivate,
    senderPublic,
    receiverPrivate,
    receiverPublic,
  }
}



describe('Signcryption - success without nonce', () => {
  it.each(cartesian([systems, encSchemes, sigSchemes, algorithms]))('over %s/%s/%s/%s', async (
    system, encScheme, sigScheme, algorithm
  ) => {
    const { senderPrivate, senderPublic, receiverPrivate, receiverPublic } = await setupKeys(
      system
    );

    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const { ciphertext, signature } = await senderPrivate.signEncrypt(
      message, receiverPublic, {
        encScheme,
        sigScheme,
        algorithm,
      }
    );
    const plaintext = await receiverPrivate.verifyDecrypt(
      ciphertext, signature, senderPublic, {
        encScheme,
        sigScheme,
        algorithm,
      }
    );
    expect(plaintext).toEqual(message);
  });
});


describe('Signcryption - success nonce', () => {
  it.each(cartesian([systems, encSchemes, sigSchemes, algorithms]))('over %s/%s/%s/%s', async (
    system, encScheme, sigScheme, algorithm
  ) => {
    const { senderPrivate, senderPublic, receiverPrivate, receiverPublic } = await setupKeys(
      system
    );

    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await randomBytes(16);
    const { ciphertext, signature } = await senderPrivate.signEncrypt(
      message, receiverPublic, {
        encScheme,
        sigScheme,
        algorithm,
        nonce,
      }
    );
    const plaintext = await receiverPrivate.verifyDecrypt(
      ciphertext, signature, senderPublic,{
        encScheme,
        sigScheme,
        algorithm,
        nonce,
      }
    );
    expect(plaintext).toEqual(message);
  });
});
