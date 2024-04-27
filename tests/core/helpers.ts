import { ElgamalSchemes, ElgamalScheme, Label } from '../../src/schemes';
import { generateKey } from '../../src';
import { partialPermutations } from '../helpers';
import { distributeKey } from '../../src/core';


export const createKeyDistributionSetup = async (opts: {
  label: Label,
  nrShares: number,
  threshold: number,
}) => {
  const { label, nrShares, threshold } = opts;
  const { privateKey, publicKey, ctx } = await generateKey(label);
  const sharing = await distributeKey(ctx, nrShares, threshold, privateKey);
  const privateShares = await sharing.getSecretShares();
  const publicShares = await sharing.getPublicShares();
  return {
    privateKey,
    publicKey,
    privateShares,
    publicShares,
    ctx,
  }
}


export const createThresholdDecryptionSetup = async (opts: {
  label: Label,
  scheme: ElgamalScheme,
  nrShares: number,
  threshold: number,
  invalidIndexes?: number[],
}) => {
  const { scheme, label, nrShares, threshold } = opts;
  const {
    privateKey,
    publicKey,
    privateShares,
    publicShares,
    ctx,
  } = await createKeyDistributionSetup({ label, nrShares, threshold, });
  const message = scheme == ElgamalSchemes.PLAIN ?
    (await ctx.randomPoint()).toBytes() :
    Uint8Array.from(Buffer.from('destroy earth'));
  const { ciphertext, decryptor } = await publicKey.encrypt(message, { scheme });
  const partialDecryptors = [];
  for (const privateShare of privateShares) {
    const share = await privateShare.generatePartialDecryptor(ciphertext);
    partialDecryptors.push(share);
  }
  const invalidDecryptors = [];
  const invalidIndexes = opts.invalidIndexes || [];
  if (invalidIndexes) {
    for (const share of partialDecryptors) {
      invalidDecryptors.push(!(invalidIndexes.includes(share.index)) ? share : {
        value: await privateKey.ctx.randomPoint(),
        index: share.index,
        proof: share.proof,
      });
    }
  }
  return {
    privateKey,
    publicKey,
    privateShares,
    publicShares,
    message,
    ciphertext,
    decryptor,
    partialDecryptors,
    invalidDecryptors,
    invalidIndexes,
    ctx,
  }
}
