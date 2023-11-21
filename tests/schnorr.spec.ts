import { schnorr, backend } from '../src';
import { Systems, Algorithms } from '../src/enums';
import { cartesian } from './helpers';

const __labels      = Object.values(Systems);
const __algorithms  = [Algorithms.SHA256, Algorithms.SHA512, undefined];

describe('Signature verification - success', () => {
  it.each(cartesian([__labels, __algorithms]))('over %s/%s', async (label, algorithm) => {
    const ctx = backend.initGroup(label);
    const { secret, pub } = await ctx.generateKeypair();
    const message = Uint8Array.from(Buffer.from('destroy earth'));
    const signature = await schnorr(ctx, algorithm).signBytes(secret, message);
    const verified = await schnorr(ctx).verifyBytes(pub, message, signature);
    expect(verified).toBe(true);
  });
});
