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

export async function combinePartialDecryptors<P extends Point>(
  ctx: Group<P>,
  shares: PartialDecryptor[],
  threshold?: number,
): Promise<Uint8Array> {
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


export async function recoverDecryptor<P extends Point>(
  ctx: Group<P>,
  shares: PartialDecryptor[],
  ciphertext: Ciphertext,
  publicShares: PublicKeyShare<P>[],
  opts?: {
    algorithm?: Algorithm,
    nonce?: Uint8Array, // TODO: Individual decryptor nonces
    threshold?: number,
    errorOnInvalid?: boolean,
  },
): Promise<{ result: Uint8Array, blame: number[] }> {
  const threshold = opts ? opts.threshold : undefined;
  if (threshold && shares.length < threshold) throw new Error(
    'Insufficient number of shares'
  );
  const { order, neutral, exp, operate, unpackValid } = ctx;
  const qualifiedIndexes = shares.map(share => share.index);
  let blame = [];
  let acc = neutral;
  const errorOnInvalid = opts ? (opts.errorOnInvalid == undefined ? true : opts.errorOnInvalid) : true;
  for (const partialDecryptor of shares) {
    const { value, index } = partialDecryptor;
    const publicShare = publicShares.filter(s => s.index == index)[0];
    if (!publicShare) throw new Error(`No public share with index ${index}`);
    try {
      const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
      const nonce = opts ? (opts.nonce || undefined) : undefined;
      await publicShare.verifyPartialDecryptor(
        ciphertext,
        partialDecryptor,
        {
          algorithm,
          nonce,
        }
      );
    } catch (err: any) {
      if (err instanceof InvalidPartialDecryptor) {
        if (errorOnInvalid) throw new Error(
          `Invalid partial decryptor with index ${index}`
        );
        blame.push(index);
      } else {
        throw err;
      }
    }
    const lambda = computeLambda(ctx, index, qualifiedIndexes);
    const curr = await exp(await unpackValid(value), lambda);
    acc = await operate(acc, curr);
  }
  const result = acc.toBytes();
  return { result, blame };
}


export async function thresholdDecrypt<P extends Point>(
  ctx: Group<P>,
  ciphertext: Ciphertext,
  decryptorShares: PartialDecryptor[],
  publicShares: PublicKeyShare<P>[],
  opts: {
    scheme: ElgamalScheme,
    mode?: BlockMode,
    encAlgorithm?: Algorithm,
    vrfAlgorithm?: Algorithm,
    nonce?: Uint8Array,
    threshold?: number,
    errorOnInvalid?: boolean
  },
): Promise<{ plaintext: Uint8Array, blame: number[] }> {
  const { result: decryptor, blame } = await recoverDecryptor(
    ctx,
    decryptorShares,
    ciphertext,
    publicShares,
    {
      algorithm: opts.vrfAlgorithm || Algorithms.DEFAULT,
      nonce: opts.nonce || undefined,
      threshold: opts.threshold || undefined,
      errorOnInvalid: opts.errorOnInvalid || true,
    }
  );
  const plaintext = await elgamal(
    ctx,
    opts.scheme,
    opts.encAlgorithm || Algorithms.DEFAULT,
    opts.mode || BlockModes.DEFAULT,
  ).decryptWithDecryptor(ciphertext, decryptor);
  return { plaintext, blame };
}
