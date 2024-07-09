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


export type IndexedNonce = { nonce: Uint8Array, index: number };


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
  partialDecryptors: PartialDecryptor[],
  threshold?: number,
): Promise<Uint8Array> {
  if (threshold && partialDecryptors.length < threshold) throw new Error(
    'Insufficient number of shares'
  );
  const { order, neutral, exp, operate, unpackValid } = ctx;
  const qualifiedIndexes = partialDecryptors.map(share => share.index);
  let acc = neutral;
  for (const share of partialDecryptors) {
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
    nonces?: IndexedNonce[],
    threshold?: number,
    errorOnInvalid?: boolean,
  },
): Promise<{ recovered: Uint8Array, blame: number[] }> {
  const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
  const threshold = opts ? opts.threshold : undefined;
  const nonces = opts ? opts.nonces : undefined;
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
      let nonce = undefined;
      if (nonces) {
        const indexedNonce = nonces.filter((n: IndexedNonce) => n.index == packet.index)[0];  // TODO: pop
        if (!indexedNonce)
          throw new Error(`No nonce for index ${packet.index}`);
        nonce = indexedNonce.nonce;
      }
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
    nonces?: IndexedNonce[],
    threshold?: number,
    errorOnInvalid?: boolean,
  },
): Promise<{ recovered: PublicKey<P>, blame: number[] }> {
  const { recovered: publicBytes, blame } = await recoverPublic(ctx, packets, opts);
  const recovered = new PublicKey(ctx, publicBytes);
  return { recovered, blame };
}


export async function recoverDecryptor<P extends Point>(
  ctx: Group<P>,
  partialDecryptors: PartialDecryptor[],
  ciphertext: Ciphertext,
  partialPublicKeys: PartialPublic<P>[],
  opts?: {
    algorithm?: Algorithm,
    nonces?: IndexedNonce[],
    threshold?: number,
    errorOnInvalid?: boolean,
  },
): Promise<{ recovered: Uint8Array, blame: number[] }> {
  const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
  const threshold = opts ? opts.threshold : undefined;
  const nonces = opts ? opts.nonces : undefined;
  const errorOnInvalid = opts ? (opts.errorOnInvalid == undefined ? true : opts.errorOnInvalid) : true;
  if (threshold && partialDecryptors.length < threshold) throw new Error(
    'Insufficient number of shares'
  );
  const { order, neutral, exp, operate, unpackValid } = ctx;
  const qualifiedIndexes = partialDecryptors.map(share => share.index);
  let blame = [];
  let acc = neutral;
  for (const partialDecryptor of partialDecryptors) {
    const { value, index } = partialDecryptor;
    // select respective public share
    const publicShare = partialPublicKeys.filter(s => s.index == index)[0];  // TODO: pop
    if (!publicShare)
      throw new Error(`No public share with index ${index}`);
    // select respective nonce
    let nonce = undefined;
    if (nonces) {
      const indexedNonce = nonces.filter((n: IndexedNonce) => n.index == index)[0];  // TODO: pop
      if (!indexedNonce)
        throw new Error(`No nonce for index ${index}`);
      nonce = indexedNonce.nonce;
    }
    try {
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
  partialDecryptors: PartialDecryptor[],
  partialPublicKeys: PartialPublic<P>[],
  opts: {
    scheme: ElgamalScheme,
    mode?: BlockMode,
    encAlgorithm?: Algorithm,
    vrfAlgorithm?: Algorithm,
    nonces?: IndexedNonce[],
    threshold?: number,
    errorOnInvalid?: boolean
  },
): Promise<{ plaintext: Uint8Array, blame: number[] }> {
  const { recovered: decryptor, blame } = await recoverDecryptor(
    ctx,
    partialDecryptors,
    ciphertext,
    partialPublicKeys,
    {
      algorithm: opts.vrfAlgorithm || Algorithms.DEFAULT,
      nonces: opts.nonces,
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
