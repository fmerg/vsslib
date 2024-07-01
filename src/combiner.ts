import { leInt2Buff } from './arith';
import { Point, Group } from './backend';
import { Ciphertext } from './elgamal';
import {
  SecretShare,
  PublicShare,
  PublicPacket,
  parsePublicPacket,
} from './dealer';
import {
  PrivateKey,
  PublicKey,
  PartialKey,
  PartialPublic,
  PartialDecryptor
} from './keys';
import { InvalidPublicShare, InvalidPartialDecryptor } from './errors';
import { BlockModes, Algorithms } from './enums';
import { ElgamalScheme, BlockMode, Algorithm } from './types';
import { mod, modInv } from './arith';

import elgamal from './elgamal';


const __0n = BigInt(0);
const __1n = BigInt(1);


export function computeLambda<P extends Point>(
  ctx: Group<P>,
  index: number,
  qualifiedIndexes: number[]
): bigint {
  let lambda = __1n;
  const { order } = ctx
  const i = index;
  qualifiedIndexes.forEach(j => {
    if (i != j) {
      const curr = BigInt(j) * modInv(BigInt(j - i), order);
      lambda = mod(lambda * curr, order);
    }
  });
  return lambda;
}


export async function combineSecretShares<P extends Point>(
  ctx: Group<P>,
  shares: SecretShare[],
  threshold?: number
): Promise<Uint8Array> {
  if (threshold && shares.length < threshold)
    throw new Error('Insufficient number of shares');
  const { order, leBuff2Scalar } = ctx;
  const indexes = shares.map(share => share.index);
  const secret = shares.reduce(
    (acc, { value, index }) => {
      const lambda = computeLambda(ctx, index, indexes);
      return mod(acc + leBuff2Scalar(value) * lambda, order);
    },
    __0n
  );
  return leInt2Buff(secret);
}


export async function combinePublicShares<P extends Point>(
  ctx: Group<P>,
  shares: PublicShare[],
  threshold?: number
): Promise<Uint8Array> {
  if (threshold && shares.length < threshold)
    throw new Error('Insufficient number of shares');
  const { order, operate, neutral, exp, unpackValid } = ctx;
  const indexes = shares.map(share => share.index);
  let acc = neutral;
  for (const { index, value } of shares) {
    const lambda = computeLambda(ctx, index, indexes);
    const curr = await unpackValid(value);
    acc = await operate(acc, await exp(curr, lambda));
  }
  return acc.toBytes();
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


export async function recoverPublic<P extends Point>(
  ctx: Group<P>,
  packets: PublicPacket[],
  opts?: {
    algorithm?: Algorithm,
    nonce?: Uint8Array, // TODO: Individual nonces
    threshold?: number,
    errorOnInvalid?: boolean,
  },
): Promise<{ recovered: Uint8Array, blame: number[] }> {
  const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
  const nonce = opts ? (opts.nonce || undefined) : undefined;
  const threshold = opts ? opts.threshold : undefined;
  const errorOnInvalid = opts ? (opts.errorOnInvalid == undefined ? true : opts.errorOnInvalid) : true;
  if (threshold && packets.length < threshold) throw new Error(
    'Insufficient number of shares'
  );
  const indexes = packets.map(packet => packet.index);
  const { order, operate, neutral, exp, unpackValid } = ctx;
  let acc = neutral;
  const blame = [];
  for (const packet of packets) {
    try {
      const { value, index } = await parsePublicPacket(ctx, packet, { algorithm, nonce });
      const lambda = computeLambda(ctx, index, indexes);
      const curr = await unpackValid(value);
      acc = await operate(acc, await exp(curr, lambda));
    } catch (err: any) {
      if (err instanceof InvalidPublicShare) {
        if (errorOnInvalid) throw err;
        blame.push(packet.index);
      }
      else throw err;
    }
  }
  return { recovered: acc .toBytes(), blame };
}


export async function recoverPublicKey<P extends Point>(
  ctx: Group<P>,
  packets: PublicPacket[],
  opts?: {
    algorithm?: Algorithm,
    nonce?: Uint8Array, // TODO: Individual nonces
    threshold?: number,
    errorOnInvalid?: boolean,
  },
): Promise<{ recovered: PublicKey<P>, blame: number[] }> {
  const { recovered: value, blame } = await recoverPublic(ctx, packets, opts);
  const recovered = new PublicKey(ctx, value);
  return { recovered, blame };
}


export async function recoverDecryptor<P extends Point>(
  ctx: Group<P>,
  shares: PartialDecryptor[],
  ciphertext: Ciphertext,
  publicShares: PartialPublic<P>[],
  opts?: {
    algorithm?: Algorithm,
    nonce?: Uint8Array, // TODO: Individual decryptor nonces
    threshold?: number,
    errorOnInvalid?: boolean,
  },
): Promise<{ recovered: Uint8Array, blame: number[] }> {
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
  return { recovered: acc.toBytes(), blame };
}


export async function thresholdDecrypt<P extends Point>(
  ctx: Group<P>,
  ciphertext: Ciphertext,
  decryptorShares: PartialDecryptor[],
  publicShares: PartialPublic<P>[],
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
  const { recovered: decryptor, blame } = await recoverDecryptor(
    ctx,
    decryptorShares,
    ciphertext,
    publicShares,
    {
      algorithm: opts.vrfAlgorithm || Algorithms.DEFAULT,
      nonce: opts.nonce,
      threshold: opts.threshold,
      errorOnInvalid: opts.errorOnInvalid,
    }
  );

  if (blame.length > 0)
    return { plaintext: Uint8Array.from([]), blame };

  const plaintext = await elgamal(
    ctx,
    opts.scheme,
    opts.encAlgorithm || Algorithms.DEFAULT,
    opts.mode || BlockModes.DEFAULT,
  ).decryptWithDecryptor(ciphertext, decryptor);
  return { plaintext, blame };
}
