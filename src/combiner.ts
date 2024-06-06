import { Point, Group } from './backend/abstract';
import { Ciphertext } from './elgamal';
import {
  PublicShare,
  computeLambda,
  reconstructSecret,
  reconstructPublic,
} from './shamir';
import {
  PrivateKey,
  PublicKey,
  PrivateKeyShare,
  PublicKeyShare,
  PartialDecryptor
} from './keys';
import { ErrorMessages } from './errors';
import { AesModes, Algorithms } from './enums';
import { ElgamalScheme, AesMode, Algorithm } from './types';

import elgamal from './elgamal';


export async function reconstructKey<P extends Point>(
  ctx: Group<P>,
  shares: PrivateKeyShare<P>[],
  threshold?: number
): Promise<PrivateKey<P>> {
  if (threshold && shares.length < threshold)
    throw new Error(ErrorMessages.INSUFFICIENT_NR_SHARES);
  return new PrivateKey(ctx, await reconstructSecret(ctx, shares.map(s => {
      return {
        value: s.bytes,
        index: s.index,
      }
    })
  ));
}

export async function reconstructPublicKey<P extends Point>(
  ctx: Group<P>,
  shares: PublicKeyShare<P>[],
  threshold?: number
): Promise<PublicKey<P>> {
  if (threshold && shares.length < threshold)
    throw new Error(ErrorMessages.INSUFFICIENT_NR_SHARES);
  const pubShares = new Array<PublicShare>(shares.length);
  for (let i = 0; i < pubShares.length; i++) {
    pubShares[i] = shares[i].asPublicShare();
  }
  const combined = await reconstructPublic(ctx, pubShares);
  return new PublicKey(ctx, combined);
}

// TODO: Include indexed nonces option?
export async function verifyPartialDecryptors<P extends Point>(
  ctx: Group<P>,
  ciphertext: Ciphertext,
  publicShares: PublicKeyShare<P>[],
  shares: PartialDecryptor[],
  opts?: { threshold?: number, raiseOnInvalid?: boolean },
): Promise<{ flag: boolean, indexes: number[]}> {
  const threshold = opts ? opts.threshold : undefined;
  if (threshold && shares.length < threshold) throw new Error(
    ErrorMessages.INSUFFICIENT_NR_SHARES
  );
  const selectPublicShare = (index: number, shares: PublicKeyShare<P>[]) => {
    const selected = shares.filter(share => share.index == index)[0];
    if (!selected) throw new Error('No share with index');
    return selected;
  }
  let flag = true;
  let indexes = [];
  const raiseOnInvalid = opts ? (opts.raiseOnInvalid || false) : false;
  for (const partialDecryptor of shares) {
    const publicShare = selectPublicShare(partialDecryptor.index, publicShares);
    const verified = await publicShare.verifyPartialDecryptor(
      ciphertext,
      partialDecryptor,
      {
        raiseOnInvalid: false,
      }
    );
    if (!verified && raiseOnInvalid)
      throw new Error(ErrorMessages.INVALID_PARTIAL_DECRYPTOR);
    flag &&= verified;
    if(!verified) indexes.push(partialDecryptor.index);
  }
  return { flag, indexes };
}

export async function reconstructDecryptor<P extends Point>(
  ctx: Group<P>,
  shares: PartialDecryptor[],
  opts?: { threshold?: number, publicShares?: PublicKeyShare<P>[] }
): Promise<Uint8Array> {
  // TODO: Include validation
  const threshold = opts ? opts.threshold : undefined;
  if (threshold && shares.length < threshold) throw new Error(
    ErrorMessages.INSUFFICIENT_NR_SHARES
  );
  const { order, neutral, exp, operate, unpackValid } = ctx;
  const qualifiedIndexes = shares.map(share => share.index);
  let acc = neutral;
  for (const share of shares) {
    const { value, index } = share;
    const lambda = computeLambda(ctx, index, qualifiedIndexes);
    const curr = await exp(lambda, await unpackValid(value));
    acc = await operate(acc, curr);
  }
  return acc.toBytes();
}


export async function thresholdDecrypt<P extends Point>(
  ctx: Group<P>,
  ciphertext: Ciphertext,
  shares: PartialDecryptor[],
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
  algorithm = algorithm || Algorithms.DEFAULT;
  mode = mode || AesModes.DEFAULT;
  return elgamal(ctx, scheme, algorithm, mode).decryptWithDecryptor(
    ciphertext,
    decryptor,
  );
}
