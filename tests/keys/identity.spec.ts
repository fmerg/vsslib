import { Algorithms } from '../../src/enums';
import { Algorithm } from '../../src/types';
import { generateKey } from '../../src/core';
import { PrivateKey, PublicKey } from '../../src/keys';
import { ErrorMessages } from '../../src/errors';
import { cartesian } from '../helpers';
import { resolveTestConfig } from '../environ';

const { systems, algorithms } = resolveTestConfig();


describe('Identity proof - success without nonce', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const proof = await privateKey.proveIdentity({ algorithm });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT)
    const verified = await publicKey.verifyIdentity(proof);
    expect(verified).toBe(true);
  });
});


describe('Identity proof - success with nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const nonce = await ctx.randomBytes();
    const proof = await privateKey.proveIdentity({ nonce });
    const verified = await publicKey.verifyIdentity(proof, nonce);
    expect(verified).toBe(true);
  });
});


describe('Identity proof - failure if forged proof', () => {
  it.each(systems)('over %s', async (system) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const proof = await privateKey.proveIdentity();
    proof.commitments[0] = await ctx.randomPoint();
    await expect(publicKey.verifyIdentity(proof)).rejects.toThrow(
      ErrorMessages.INVALID_SECRET
    );
  });
});


describe('Identity proof - failure if wrong algorithm', () => {
  it.each(cartesian([systems, algorithms]))('over %s/%s', async (system, algorithm) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const proof = await privateKey.proveIdentity();
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    await expect(publicKey.verifyIdentity(proof)).rejects.toThrow(
      ErrorMessages.INVALID_SECRET
    );
  });
});


describe('Identity proof - failure if missing nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const nonce = await ctx.randomBytes();
    const proof = await privateKey.proveIdentity({ nonce });
    await expect(publicKey.verifyIdentity(proof)).rejects.toThrow(
      ErrorMessages.INVALID_SECRET
    );
  });
});


describe('Identity proof - failure if forged nonce', () => {
  it.each(systems)('over %s', async (system) => {
    const { privateKey, publicKey, ctx } = await generateKey(system);
    const nonce = await ctx.randomBytes();
    const proof = await privateKey.proveIdentity({ nonce });
    const forgedNonce = await ctx.randomBytes();
    await expect(publicKey.verifyIdentity(proof, forgedNonce)).rejects.toThrow(
      ErrorMessages.INVALID_SECRET
    );
  });
});
