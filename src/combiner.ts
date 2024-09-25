import { leInt2Buff, mod, modInv } from 'vsslib/arith';
import { Point, Group } from 'vsslib/backend';
import { unpackScalar, unpackPoint } from 'vsslib/secrets'
import { SecretShare, PublicShare } from 'vsslib/dealer';
import { SchnorrPacket, PartialPublicKey, PartialDecryptor } from 'vsslib/shareholder';
import { Ciphertext } from 'vsslib/elgamal';
import { InvalidPublicShare, InvalidPartialDecryptor, InvalidInput } from 'vsslib/errors';
import { PublicKey } from 'vsslib/keys';
import { BlockModes, Algorithms } from 'vsslib/enums';
import { ElgamalScheme, BlockMode, Algorithm } from 'vsslib/types';

import elgamal from 'vsslib/elgamal';
import nizk from 'vsslib/nizk';


const __0n = BigInt(0);
const __1n = BigInt(1);


export type IndexedNonce = { nonce: Uint8Array, index: number };


export function computeLambda<P extends Point>(
  ctx: Group<P>,
  index: number,
  indexes: number[]
): bigint {
  const order = ctx.order;
  const i = index;
  let acc = __1n;
  indexes.forEach(j => {
    if (i != j) {
      const curr = BigInt(j) * modInv(BigInt(j - i), order);
      acc = mod(acc * curr, order);
    }
  });
  return acc;
}


export async function combineSecretShares<P extends Point>(
  ctx: Group<P>,
  shares: SecretShare[],
  threshold?: number
): Promise<Uint8Array> {
  if (threshold && shares.length < threshold)
    throw new InvalidInput('Insufficient number of shares');
  const order = ctx.order;
  const indexes = shares.map(share => share.index);
  let x = __0n;
  for (const { value, index } of shares) {
    const li = computeLambda(ctx, index, indexes);
    const xi = await unpackScalar(ctx, value);
    x = mod(x + li * xi, order);
  }
  return leInt2Buff(x);
}


export async function combinePublicShares<P extends Point>(
  ctx: Group<P>,
  shares: PublicShare[],
  threshold?: number
): Promise<Uint8Array> {
  if (threshold && shares.length < threshold)
    throw new InvalidInput('Insufficient number of shares');
  const exp = ctx.exp;
  const indexes = shares.map(share => share.index);
  let y = ctx.neutral;
  for (const { value, index } of shares) {
    const li = computeLambda(ctx, index, indexes);
    const yi = await unpackPoint(ctx, value)
    y = await ctx.operate(y, await exp(yi, li));
  }
  return y.toBytes();
}


export async function combinePartialDecryptors<P extends Point>(
  ctx: Group<P>,
  shares: PartialDecryptor[],
  threshold?: number,
): Promise<Uint8Array> {
  if (threshold && shares.length < threshold) throw new InvalidInput(
    'Insufficient number of shares'
  );
  const exp = ctx.exp;
  const indexes = shares.map(share => share.index);
  let d = ctx.neutral;
  for (const share of shares) {
    const { value, index } = share;
    const li = computeLambda(ctx, index, indexes);
    const di = await unpackPoint(ctx, value)
    d = await ctx.operate(d, await exp(di, li));
  }
  return d.toBytes();
}


export async function parseSchnorrPacket<P extends Point>(
  ctx: Group<P>,
  packet: SchnorrPacket,
  opts?: {
    algorithm?: Algorithm,
    nonce?: Uint8Array,
  },
): Promise<PublicShare> {
  const { value, index, proof } = packet;
  const y = await unpackPoint(ctx, value)
  const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
  const nonce = opts ? opts.nonce : undefined;
  const isValid = await nizk(ctx, algorithm).verifyDlog(
    {
      u: ctx.generator,
      v: y,
    },
    proof,
    nonce,
  );
  if (!isValid)
    throw new InvalidPublicShare(`Invalid packet with index ${index}`);
  return { value, index };
}


export async function recoverPublic<P extends Point>(
  ctx: Group<P>,
  packets: SchnorrPacket[],
  opts?: {
    algorithm?: Algorithm,
    nonces?: IndexedNonce[],
    threshold?: number,
    errorOnInvalid?: boolean,
  },
): Promise<{ recovered: Uint8Array, blame: PublicShare[] }> {
  const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
  const threshold = opts ? opts.threshold : undefined;
  const nonces = opts ? (opts.nonces || [] ) : [];
  const errorOnInvalid = opts ? (opts.errorOnInvalid == undefined ? true : opts.errorOnInvalid) : true;
  if (threshold && packets.length < threshold) throw new InvalidInput(
    'Insufficient number of shares'
  );
  const exp = ctx.exp;
  const indexes = packets.map(packet => packet.index);
  const blame = [];
  let y = ctx.neutral;
  for (const packet of packets) {
    const packetNonce = nonces.filter((n: IndexedNonce) => n.index == packet.index)[0];  // TODO: pop
    const nonce = packetNonce ? packetNonce.nonce : undefined;
    try {
      // TODO: Improve this interface so as to remove lambda computation
      // outside the present block
      const { value, index } = await parseSchnorrPacket(ctx, packet, { algorithm, nonce });
      const li = computeLambda(ctx, index, indexes);
      const yi = await unpackPoint(ctx, value)
      y = await ctx.operate(y, await exp(yi, li));
    } catch (err: any) {
      if (err instanceof InvalidPublicShare) {
        if (errorOnInvalid) throw err;
        blame.push({
          value: packet.value,
          index: packet.index,
        });
      }
      else throw err;
    }
  }
  const recovered = y.toBytes();
  return { recovered, blame };
}


export async function recoverPublicKey<P extends Point>(
  ctx: Group<P>,
  packets: SchnorrPacket[],
  opts?: {
    algorithm?: Algorithm,
    nonces?: IndexedNonce[],
    threshold?: number,
    errorOnInvalid?: boolean,
  },
): Promise<{ recovered: PublicKey<P>, blame: PublicShare[] }> {
  const { recovered: publicBytes, blame } = await recoverPublic(ctx, packets, opts);
  const recovered = new PublicKey(ctx, publicBytes);
  return { recovered, blame };
}


export async function recoverDecryptor<P extends Point>(
  ctx: Group<P>,
  shares: PartialDecryptor[],
  ciphertext: Ciphertext,
  partialPublicKeys: PartialPublicKey<P>[],
  opts?: {
    algorithm?: Algorithm,
    nonces?: IndexedNonce[],
    threshold?: number,
    errorOnInvalid?: boolean,
  },
): Promise<{ recovered: Uint8Array, blame: PartialPublicKey<P>[] }> {
  const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
  const threshold = opts ? opts.threshold : undefined;
  const nonces = opts ? opts.nonces : undefined;
  const errorOnInvalid = opts ? (opts.errorOnInvalid == undefined ? true : opts.errorOnInvalid) : true;
  if (threshold && shares.length < threshold) throw new InvalidInput(
    'Insufficient number of shares'
  );
  const exp = ctx.exp;
  const indexes = shares.map(share => share.index);
  const blame = [];
  let d = ctx.neutral;
  for (const share of shares) {
    const { value, index } = share;
    const partialPublic = partialPublicKeys.filter(s => s.index == index)[0];  // TODO: pop
    if (!partialPublic)
      throw new InvalidInput(`No public share with index ${index}`);
    let nonce = undefined;
    if (nonces) {
      const indexedNonce = nonces.filter((n: IndexedNonce) => n.index == index)[0];  // TODO: pop
      if (!indexedNonce)
        throw new InvalidInput(`No nonce for index ${index}`);
      nonce = indexedNonce.nonce;
    }
    try {
      await partialPublic.verifyPartialDecryptor(
        ciphertext,
        share,
        {
          algorithm,
          nonce,
        }
      );
    } catch (err: any) {
      if (err instanceof InvalidPartialDecryptor) {
        if (errorOnInvalid) {
          err.message += ` with index ${index}`
          throw err;
        }
        blame.push(partialPublic);
      } else {
        throw err;
      }
    }
    const li = computeLambda(ctx, index, indexes);
    const di = await unpackPoint(ctx, value);
    d = await ctx.operate(d, await exp(di, li));
  }
  const recovered = d.toBytes();
  return { recovered, blame };
}


export async function thresholdDecrypt<P extends Point>(
  ctx: Group<P>,
  ciphertext: Ciphertext,
  partialDecryptors: PartialDecryptor[],
  partialPublicKeys: PartialPublicKey<P>[],
  opts: {
    scheme: ElgamalScheme,
    mode?: BlockMode,
    encAlgorithm?: Algorithm,
    vrfAlgorithm?: Algorithm,
    nonces?: IndexedNonce[],
    threshold?: number,
    errorOnInvalid?: boolean
  },
): Promise<{ plaintext: Uint8Array, blame: PartialPublicKey<P>[] }> {
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
