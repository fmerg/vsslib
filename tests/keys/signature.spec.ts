import { Algorithms, Algorithm, Systems } from '../../src/schemes';
import { generateKey } from '../../src/core';
import { Messages } from '../../src/keys/enums';
import { PrivateKey, PublicKey } from '../../src/keys';
import { cartesian } from '../helpers';
import { resolveBackends, resolveAlgorithms } from '../environ';

const __labels      = resolveBackends();
const __algorithms  = [...resolveAlgorithms(), undefined];


describe('Schnorr signature scheme - success without nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey, ctx } = await generateKey(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    // TODO
    // expect(signature.algorithm).toBe(algorithm || Algorithms.DEFAULT);
    const signature = await privateKey.sign(message, { algorithm });
    const verified = await publicKey.verifySignature(message, signature, { algorithm });
    expect(verified).toBe(true);
  });
});


describe('Schnorr signature scheme - success with nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey, ctx } = await generateKey(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await ctx.randomBytes();
    const signature = await privateKey.sign(message, { nonce, algorithm });
    // TODO
    // expect(signature.algorithm).toBe(algorithm || Algorithms.DEFAULT); //
    const verified = await publicKey.verifySignature(message, signature, { nonce, algorithm });
    expect(verified).toBe(true);
  });
});


describe('Schnorr signature scheme - failure if forged message', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey, ctx } = await generateKey(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const signature = await privateKey.sign(message, { algorithm });
    const forgedMessage = Uint8Array.from(Buffer.from('don\' t destroy earth'));
    await expect(publicKey.verifySignature(forgedMessage, signature, { algorithm })).rejects.toThrow(
      'Invalid signature'
    );
  });
});


describe('Schnorr signature scheme - failure if forged signature', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey, ctx } = await generateKey(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const signature = await privateKey.sign(message, { algorithm });
    signature.commitment! = await ctx.randomPoint();
    await expect(publicKey.verifySignature(message, signature, { algorithm })).rejects.toThrow(
      'Invalid signature'
    );
  });
});


describe('Schnorr signature scheme - failure if wrong algorithm', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey, ctx } = await generateKey(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const signature = await privateKey.sign(message, { algorithm });
    // TODO
    const wrongAlgorithm = (algorithm == Algorithms.SHA256 || algorithm == undefined) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    await expect(publicKey.verifySignature(message, signature, { algorithm: wrongAlgorithm })).rejects.toThrow(
      'Invalid signature'
    );
  });
});


describe('Schnorr signature scheme - failure if missing nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey, ctx } = await generateKey(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await ctx.randomBytes();
    const signature = await privateKey.sign(message, { nonce, algorithm });
    await expect(publicKey.verifySignature(message, signature, { algorithm })).rejects.toThrow(
      'Invalid signature'
    );
  });
});


describe('Schnorr signature scheme - failure if forged nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey, ctx } = await generateKey(label);
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const nonce = await ctx.randomBytes();
    const signature = await privateKey.sign(message, { nonce, algorithm });
    const forgedNonce = await ctx.randomBytes();
    await expect(publicKey.verifySignature(message, signature, { nonce: forgedNonce, algorithm })).rejects.toThrow(
      'Invalid signature'
    );
  });
});
