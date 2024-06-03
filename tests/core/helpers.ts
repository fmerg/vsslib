import { Group, Point } from '../../src/backend/abstract';
import { ElgamalSchemes } from '../../src/enums';
import { ElgamalScheme, System } from '../../src/types';
import { generateKey } from '../../src';
import { randomIndex } from '../helpers';
import { SecretShare } from '../../src/shamir';
import { PrivateShare, PublicShare } from '../../src/core';


export const selectShare = (index: number, shares: PublicShare<Point>[]) => {
  const selected = shares.filter(share => share.index == index)[0];
  if (!selected) throw new Error(`No share found for index ${index}`);
  return selected;
}


export const selectPrivateShare = (index: number, shares: PrivateShare<Point>[]) => {
  const selected = shares.filter(share => share.index == index)[0];
  if (!selected) throw new Error(`No share found for index ${index}`);
  return selected;
}

export const createKeySharingSetup = async (opts: {
  system: System,
  nrShares: number,
  threshold: number,
}) => {
  const { system, nrShares, threshold } = opts;
  const { privateKey, publicKey, ctx } = await generateKey(system);
  const sharing = await privateKey.generateSharing(nrShares, threshold);
  const polynomial = sharing.polynomial;
  const secretShares = await sharing.getSecretShares();
  const privateShares = secretShares.map(({ value, index }: SecretShare<Point>) => {
    return new PrivateShare(ctx, value, index);
  });
  const publicShares = []
  for (const share of privateShares) {
    publicShares.push(await share.getPublicShare());
  }
  return {
    privateKey,
    publicKey,
    ctx,
    sharing,
    polynomial,
    privateShares,
    publicShares,
  };
}


export const createThresholdDecryptionSetup = async (opts: {
  system: System,
  scheme: ElgamalScheme,
  nrShares: number,
  threshold: number,
  nrInvalidIndexes?: number,
}) => {
  let { scheme, system, nrShares, threshold, nrInvalidIndexes } = opts;
  const {
    privateKey,
    publicKey,
    privateShares,
    publicShares,
    ctx,
  } = await createKeySharingSetup({ system, nrShares, threshold, });
  const message = scheme == ElgamalSchemes.PLAIN ?
    (await ctx.randomPoint()).toBytes() :
    Uint8Array.from(Buffer.from('destroy earth'));
  const { ciphertext, decryptor } = await publicKey.encrypt(message, { scheme });
  const partialDecryptors = [];
  for (const privateShare of privateShares) {
    const share = await privateShare.computePartialDecryptor(ciphertext);
    partialDecryptors.push(share);
  }
  let invalidIndexes: number[] = [];
  nrInvalidIndexes = nrInvalidIndexes || 0;
  while (invalidIndexes.length < nrInvalidIndexes) {
    const index = randomIndex(1, nrShares);
    if (invalidIndexes.includes(index)) continue;
    invalidIndexes.push(index);
  }
  const invalidDecryptors = [];
  if (invalidIndexes) {
    for (const share of partialDecryptors) {
      invalidDecryptors.push(!(invalidIndexes.includes(share.index)) ? share : {
        value: (await ctx.randomPoint()).toBytes(),
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
