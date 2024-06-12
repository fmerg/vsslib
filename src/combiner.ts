import { Point, Group } from './backend/abstract';
import { Ciphertext } from './elgamal';
import {
  SecretShare,
  PublicShare,
  computeLambda,
  recoverSecret,
  recoverPublic,
  PublicSharePacket,
  combinePublics,
} from './shamir';
import {
  PrivateKey,
  PublicKey,
  PrivateKeyShare,
  PublicKeyShare,
  PartialDecryptor
} from './keys';
import { InvalidPartialDecryptor } from './errors';
import { BlockModes, Algorithms } from './enums';
import { ElgamalScheme, BlockMode, Algorithm } from './types';

import elgamal from './elgamal';


export async function recoverKey<P extends Point>(
  ctx: Group<P>,
  shares: SecretShare[],
  threshold?: number
): Promise<PrivateKey<P>> {
  const result = await recoverSecret(ctx, shares, threshold);
  return new PrivateKey(ctx, result);
}

export async function recoverPublicKey<P extends Point>(
  ctx: Group<P>,
  packets: PublicSharePacket[],
  opts?: {
    algorithm?: Algorithm,
    nonce?: Uint8Array, // TODO: Individual nonces
    threshold?: number,
    errorOnInvalid?: boolean,
  },
): Promise<{ recovered: PublicKey<P>, blame: number[] }> {
  const { result, blame } = await recoverPublic(ctx, packets, opts);
  const recovered = new PublicKey(ctx, result);
  return { recovered, blame };
}

// TODO: Include indexed nonces option?
export async function verifyPartialDecryptors<P extends Point>(
  ctx: Group<P>,
  ciphertext: Ciphertext,
  publicShares: PublicKeyShare<P>[],
  shares: PartialDecryptor[],
  opts?: { threshold?: number, errorOnInvalid?: boolean },
): Promise<{ flag: boolean, indexes: number[]}> {
  const threshold = opts ? opts.threshold : undefined;
  if (threshold && shares.length < threshold) throw new Error(
    'Insufficient number of shares'
  );
  const selectPublicShare = (index: number, shares: PublicKeyShare<P>[]) => {
    const selected = shares.filter(share => share.index == index)[0];
    if (!selected) throw new Error('No share with index');
    return selected;
  }
  let flag = true;
  let indexes = [];
  const errorOnInvalid = opts ? (opts.errorOnInvalid || false) : false;
  for (const partialDecryptor of shares) {
    const { index } = partialDecryptor;
    const publicShare = selectPublicShare(index, publicShares);
    try {
      await publicShare.verifyPartialDecryptor(
        ciphertext,
        partialDecryptor,
      );
    } catch (err: any) {
      if (err instanceof InvalidPartialDecryptor) {
        if (errorOnInvalid)
          throw new Error(`Invalid partial decryptor with index ${index}`);
        indexes.push(index);
        flag &&= false;
      } else {
        throw err;
      }
    }
  }
  return { flag, indexes };
}

export async function recoverDecryptor<P extends Point>(
  ctx: Group<P>,
  shares: PartialDecryptor[],
  opts?: { threshold?: number, publicShares?: PublicKeyShare<P>[] }
): Promise<Uint8Array> {
  // TODO: Include validation
  const threshold = opts ? opts.threshold : undefined;
  if (threshold && shares.length < threshold) throw new Error(
    'Insufficient number of shares'
  );
  const { order, neutral, exp, operate, unpackValid } = ctx;
  const qualifiedIndexes = shares.map(share => share.index);
  let acc = neutral;
  for (const share of shares) {
    const { value, index } = share;
    const lambda = computeLambda(ctx, index, qualifiedIndexes);
    const curr = await exp(await unpackValid(value), lambda);
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
    mode?: BlockMode,
    algorithm?: Algorithm,
    threshold?: number,
  },
): Promise<Uint8Array> {
  let { scheme, mode, algorithm, threshold } = opts;
  // TODO: Include public schares option for validation?
  const decryptor = await recoverDecryptor(ctx, shares, { threshold });
  algorithm = algorithm || Algorithms.DEFAULT;
  mode = mode || BlockModes.DEFAULT;
  return elgamal(ctx, scheme, algorithm, mode).decryptWithDecryptor(
    ciphertext,
    decryptor,
  );
}
