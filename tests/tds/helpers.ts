import { ElgamalSchemes, ElgamalScheme, Label } from '../../src/schemes';
import { Point } from '../../src/backend/abstract'
import { key, backend } from '../../src';
import { PrivateKey, PublicKey, PrivateShare, PublicShare } from '../../src/key';
import { PartialDecryptor } from '../../src/tds';
import { partialPermutations } from '../helpers';
import { resolveBackend } from '../environ';
import tds from '../../src/tds';


export const createKeyDistributionSetup = async (opts: {
  label: Label,
  nrShares: number,
  threshold: number,
}) => {
  const { label, nrShares, threshold } = opts;
  const { privateKey, publicKey } = await key.generate(label);
  const sharing = await privateKey.distribute(nrShares, threshold);
  const privateShares = await sharing.getSecretShares();
  const publicShares = await sharing.getPublicShares();
  const ctx = backend.initGroup(label);
  const combiner = tds(ctx, threshold);
  return {
    privateKey,
    publicKey,
    privateShares,
    publicShares,
    combiner,
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
    combiner,
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
    combiner,
  }
}
