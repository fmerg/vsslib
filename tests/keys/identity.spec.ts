import { Algorithms, Algorithm, Systems } from '../../src/schemes';
import { Messages } from '../../src/keys/enums';
const { backend, keys, PrivateKey, PublicKey } = require('../../src')
import { cartesian } from '../helpers';
import { resolveBackends, resolveAlgorithms } from '../environ';

const __labels      = resolveBackends();
const __algorithms  = resolveAlgorithms();


describe('Identity proof - success without nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey, ctx } = await keys.generate(label);
    const proof = await privateKey.proveIdentity({ algorithm });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT)
    const verified = await publicKey.verifyIdentity(proof);
    expect(verified).toBe(true);
  });
});


describe('Identity proof - success with nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey, ctx } = await keys.generate(label);
    const nonce = await ctx.randomBytes();
    const proof = await privateKey.proveIdentity({ nonce });
    const verified = await publicKey.verifyIdentity(proof, nonce);
    expect(verified).toBe(true);
  });
});


describe('Identity proof - failure if forged proof', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey, ctx } = await keys.generate(label);
    const proof = await privateKey.proveIdentity();
    proof.commitments[0] = await ctx.randomPoint();
    await expect(publicKey.verifyIdentity(proof)).rejects.toThrow(
      Messages.INVALID_IDENTITY_PROOF
    );
  });
});


describe('Identity proof - failure if wrong algorithm', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const { privateKey, publicKey, ctx } = await keys.generate(label);
    const proof = await privateKey.proveIdentity();
    proof.algorithm = (proof.algorithm == Algorithms.SHA256) ?
      Algorithms.SHA512 :
      Algorithms.SHA256;
    await expect(publicKey.verifyIdentity(proof)).rejects.toThrow(
      Messages.INVALID_IDENTITY_PROOF
    );
  });
});


describe('Identity proof - failure if missing nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey, ctx } = await keys.generate(label);
    const nonce = await ctx.randomBytes();
    const proof = await privateKey.proveIdentity({ nonce });
    await expect(publicKey.verifyIdentity(proof)).rejects.toThrow(
      Messages.INVALID_IDENTITY_PROOF
    );
  });
});


describe('Identity proof - failure if forged nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey, ctx } = await keys.generate(label);
    const nonce = await ctx.randomBytes();
    const proof = await privateKey.proveIdentity({ nonce });
    const forgedNonce = await ctx.randomBytes();
    await expect(publicKey.verifyIdentity(proof, forgedNonce)).rejects.toThrow(
      Messages.INVALID_IDENTITY_PROOF
    );
  });
});
