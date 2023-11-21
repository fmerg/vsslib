import { Algorithms, Systems } from '../../src/enums';
import { Messages } from '../../src/key/enums';
import { Algorithm } from '../../src/types';
const { backend, key, PrivateKey, PublicKey } = require('../../src')
import { cartesian } from '../helpers';

const __labels = Object.values(Systems);
const __algorithms  = [...Object.values(Algorithms), undefined];


describe('Identity proof - success without nonce', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s%s', async (label, algorithm) => {
    const { privateKey, publicKey } = await key.generate(label);
    const proof = await privateKey.proveIdentity({ algorithm });
    expect(proof.algorithm).toBe(algorithm || Algorithms.DEFAULT)
    const verified = await publicKey.verifyIdentity(proof);
    expect(verified).toBe(true);
  });
});


describe('Identity proof - success with nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey } = await key.generate(label);
    const nonce = await privateKey.ctx.randomBytes();
    const proof = await privateKey.proveIdentity({ nonce });
    const verified = await publicKey.verifyIdentity(proof, nonce);
    expect(verified).toBe(true);
  });
});


describe('Identity proof - failure if forged proof', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey } = await key.generate(label);
    const proof = await privateKey.proveIdentity();
    proof.commitments[0] = await privateKey.ctx.randomPoint();
    await expect(publicKey.verifyIdentity(proof)).rejects.toThrow(
      Messages.INVALID_IDENTITY_PROOF
    );
  });
});


describe('Identity proof - failure if wrong algorithm', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s%s', async (label, algorithm) => {
    const { privateKey, publicKey } = await key.generate(label);
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
    const { privateKey, publicKey } = await key.generate(label);
    const nonce = await privateKey.ctx.randomBytes();
    const proof = await privateKey.proveIdentity({ nonce });
    await expect(publicKey.verifyIdentity(proof)).rejects.toThrow(
      Messages.INVALID_IDENTITY_PROOF
    );
  });
});


describe('Identity proof - failure if forged nonce', () => {
  it.each(__labels)('over %s', async (label) => {
    const { privateKey, publicKey } = await key.generate(label);
    const nonce = await privateKey.ctx.randomBytes();
    const proof = await privateKey.proveIdentity({ nonce });
    const forgedNonce = await publicKey.ctx.randomBytes();
    await expect(publicKey.verifyIdentity(proof, forgedNonce)).rejects.toThrow(
      Messages.INVALID_IDENTITY_PROOF
    );
  });
});
