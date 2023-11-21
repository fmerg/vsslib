import { Algorithms, Systems } from '../../src/enums';
import { Messages } from '../../src/key/enums';
import { Algorithm } from '../../src/types';
const { backend, key, PrivateKey, PublicKey } = require('../../src')
import { cartesian } from '../helpers';

const __labels = Object.values(Systems);
const __algorithms  = [...Object.values(Algorithms), undefined];


describe('Schnorr signature scheme - success without nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey } = await key.generate(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const signature = await privateKey.sign(message, { algorithm });
    expect(signature.algorithm).toBe(algorithm || Algorithms.DEFAULT);
    const verified = await publicKey.verifySignature(message, signature);
    expect(verified).toBe(true);
  });
});


describe('Schnorr signature scheme - success with nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey } = await key.generate(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await privateKey.ctx.randomBytes();
    const signature = await privateKey.sign(message, { nonce, algorithm });
    expect(signature.algorithm).toBe(algorithm || Algorithms.DEFAULT);
    const verified = await publicKey.verifySignature(message, signature, nonce);
    expect(verified).toBe(true);
  });
});


describe('Schnorr signature scheme - failure if forged message', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey } = await key.generate(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const signature = await privateKey.sign(message, { algorithm });
    const forgedMessage = Uint8Array.from(Buffer.from('don\' t destroy earth'));
    await expect(publicKey.verifySignature(forgedMessage, signature)).rejects.toThrow(
      'Invalid signature'
    );
  });
});


describe('Schnorr signature scheme - failure if forged signature', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey } = await key.generate(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const signature = await privateKey.sign(message, { algorithm });
    signature.commitments[0] = await privateKey.ctx.randomPoint();
    await expect(publicKey.verifySignature(message, signature)).rejects.toThrow(
      'Invalid signature'
    );
  });
});


describe('Schnorr signature scheme - failure if wrong algorithm', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey } = await key.generate(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const signature = await privateKey.sign(message, { algorithm });
    signature.algorithm = (signature.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    await expect(publicKey.verifySignature(message, signature)).rejects.toThrow(
      'Invalid signature'
    );
  });
});


describe('Schnorr signature scheme - failure if missing nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey } = await key.generate(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await privateKey.ctx.randomBytes();
    const signature = await privateKey.sign(message, { nonce, algorithm });
    await expect(publicKey.verifySignature(message, signature)).rejects.toThrow(
      'Invalid signature'
    );
  });
});


describe('Schnorr signature scheme - failure if forged nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey } = await key.generate(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await privateKey.ctx.randomBytes();
    const signature = await privateKey.sign(message, { nonce, algorithm });
    const forgedNonce = await privateKey.ctx.randomBytes();
    await expect(publicKey.verifySignature(message, signature, forgedNonce)).rejects.toThrow(
      'Invalid signature'
    );
  });
});
