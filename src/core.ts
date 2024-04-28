import { Point, Group } from './backend/abstract';
import { initGroup } from './backend';
import { leInt2Buff } from './crypto/bitwise';
import { ElgamalCiphertext } from './crypto/elgamal';
import { NizkProof } from './nizk';
import { BaseShare } from './base';
import { PrivateKey, PublicKey } from './keys';
import { ErrorMessages } from './errors';
import { PrivateShare, PublicShare, PartialDecryptor, KeySharing } from './sharing';
import { ElgamalSchemes, AesModes, Algorithms } from './enums';
import { ElgamalScheme, AesMode, Algorithm, System } from './types';

const shamir = require('./shamir');
const elgamal = require('./crypto/elgamal');
const backend = require('./backend');


type KeyPair<P extends Point> = { privateKey: PrivateKey<P>, publicKey: PublicKey<P>, ctx: Group<P> };

export async function generateKey(system: System): Promise<KeyPair<Point>> {
  const ctx = initGroup(system);
  const privateKey = new PrivateKey(ctx, await ctx.randomBytes());
  const publicKey = await privateKey.publicKey();
  return { privateKey, publicKey, ctx };
}


export async function distributeKey<P extends Point>(
  ctx: Group<P>,
  nrShares: number,
  threshold: number,
  privateKey: PrivateKey<P>
): Promise<KeySharing<P>> {
  const { polynomial } = await shamir.shareSecret(
    ctx, nrShares, threshold, privateKey.secret
  );
  return new KeySharing(ctx, nrShares, threshold, polynomial);
}

export async function reconstructKey<P extends Point>(
  ctx: Group<P>,
  shares: PrivateShare<P>[],
  threshold?: number
): Promise<PrivateKey<P>> {
  if (threshold && shares.length < threshold) throw new Error(
    ErrorMessages.INSUFFICIENT_NR_SHARES
  );
  const secretShares = shares.map(({ secret: value, index }) => { return { value, index } });
  const secret = await shamir.reconstructSecret(ctx, secretShares);
  return new PrivateKey(ctx, leInt2Buff(secret));
}

export async function reconstructPublic<P extends Point>(
  ctx: Group<P>,
  shares: PublicShare<P>[],
  threshold?: number
): Promise<PublicKey<P>> {
  if (threshold && shares.length < threshold) throw new Error(
    ErrorMessages.INSUFFICIENT_NR_SHARES
  );
  const pubShares = shares.map(({ pub: value, index }) => { return { value, index } });
  const pub = await shamir.reconstructPublic(ctx, pubShares);
  return new PublicKey(ctx, pub);
}

// TODO: Include indexed nonces option?
export async function verifyPartialDecryptors<P extends Point>(
  ctx: Group<P>,
  ciphertext: ElgamalCiphertext<P>,
  publicShares: PublicShare<P>[],
  shares: PartialDecryptor<P>[],
  opts?: { threshold?: number, raiseOnInvalid?: boolean },
): Promise<{ flag: boolean, indexes: number[]}> {
  const threshold = opts ? opts.threshold : undefined;
  if (threshold && shares.length < threshold) throw new Error(
    ErrorMessages.INSUFFICIENT_NR_SHARES
  );
  const selectPublicShare = (index: number, shares: PublicShare<P>[]) => {
    const selected = shares.filter(share => share.index == index)[0];
    if (!selected) throw new Error('No share with index');
    return selected;
  }
  let flag = true;
  let indexes = [];
  const raiseOnInvalid = opts ? (opts.raiseOnInvalid || false) : false;
  for (const partialDecryptor of shares) {
    const publicShare = selectPublicShare(partialDecryptor.index, publicShares);
    const verified = await publicShare.verifyPartialDecryptor(ciphertext, partialDecryptor, {
      raiseOnInvalid: false,
    });
    if (!verified && raiseOnInvalid)
      throw new Error(ErrorMessages.INVALID_PARTIAL_DECRYPTOR);
    flag &&= verified;
    if(!verified) indexes.push(partialDecryptor.index);
  }
  return { flag, indexes };
}

export async function reconstructDecryptor<P extends Point>(
  ctx: Group<P>,
  shares: PartialDecryptor<P>[],
  opts?: { threshold?: number, publicShares?: PublicShare<P>[] }
): Promise<P> {
  // TODO: Include validation
  const threshold = opts ? opts.threshold : undefined;
  if (threshold && shares.length < threshold) throw new Error(
    ErrorMessages.INSUFFICIENT_NR_SHARES
  );
  const { order, neutral, operate, combine } = ctx;
  const qualifiedIndexes = shares.map(share => share.index);
  let acc = neutral;
  for (const share of shares) {
    const { value, index } = share;
    const lambda = shamir.computeLambda(ctx, index, qualifiedIndexes);
    const curr = await operate(lambda, value);
    acc = await combine(acc, curr);
  }
  return acc;
}

export async function thresholdDecrypt<P extends Point>(
  ctx: Group<P>,
  ciphertext: ElgamalCiphertext<P>,
  shares: PartialDecryptor<P>[],
  opts: {
    scheme: ElgamalScheme,
    mode?: AesMode,
    algorithm?: Algorithm,
    threshold?: number,
  },
): Promise<Uint8Array> {
  let { scheme, mode, algorithm, threshold } = opts;
  // TODO: Include public schares option for validation?
  const decryptor = await reconstructDecryptor(ctx, shares, { threshold });
  switch (scheme) {
    case ElgamalSchemes.IES:
      mode = mode || AesModes.DEFAULT;
      algorithm = algorithm || Algorithms.DEFAULT;
      return elgamal[ElgamalSchemes.IES](ctx, mode, algorithm).decryptWithDecryptor(
        ciphertext, decryptor,
      );
    case ElgamalSchemes.KEM:
      mode = mode || AesModes.DEFAULT;
      return elgamal[ElgamalSchemes.KEM](ctx, mode).decryptWithDecryptor(
        ciphertext, decryptor,
      );
    case ElgamalSchemes.PLAIN:
      return elgamal[ElgamalSchemes.PLAIN](ctx).decryptWithDecryptor(
        ciphertext, decryptor
      );
  }
}
