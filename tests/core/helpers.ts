import { ElgamalSchemes, ElgamalScheme, Label } from '../../src/schemes';
import { Point } from '../../src/backend/abstract'
import { key, backend } from '../../src';
import { PrivateKey, PublicKey, PrivateShare, PublicShare } from '../../src/key';
import { PartialDecryptor } from '../../src/core';
import { partialPermutations } from '../helpers';
import { resolveBackend } from '../environ';
import { VssParty } from '../../src/core';


export const createKeyDistributionSetup = async (opts: {
  label: Label,
  nrShares: number,
  threshold: number,
}) => {
  const { label, nrShares, threshold } = opts;
  const { privateKey, publicKey } = await key.generate(label);
  const vss = new VssParty(privateKey.ctx);
  const sharing = await vss.distributeKey(nrShares, threshold, privateKey);
  const privateShares = await sharing.getSecretShares();
  const publicShares = await sharing.getPublicShares();
  const ctx = backend.initGroup(label);
  return {
    privateKey,
    publicKey,
    privateShares,
    publicShares,
    vss,
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
    vss,
    ctx,
  } = await createKeyDistributionSetup({
    label,
    nrShares,
    threshold,
  });
  let message;
  if (scheme == ElgamalSchemes.PLAIN) {
    message = (await ctx.randomPoint()).toBytes();
  } else {
    message = Uint8Array.from(Buffer.from('destroy earth'));
  }
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
    vss,
  }
}
