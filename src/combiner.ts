import { leInt2Buff, mod, modInv } from 'vsslib/arith';
import { Point, Group } from 'vsslib/backend';
import { unpackScalar, unpackPoint } from 'vsslib/secrets'
import { SecretShare, PublicShare } from 'vsslib/dealer';
import { SchnorrPacket } from 'vsslib/shareholder';
import { InvalidPublicShare, InvalidInput } from 'vsslib/errors';
import { Algorithms } from 'vsslib/enums';
import { Algorithm } from 'vsslib/types';

import nizk from 'vsslib/nizk';


const __0n = BigInt(0);
const __1n = BigInt(1);


export type Nonces = { [key: number]: Uint8Array };


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
    nonces?: Nonces,
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
    const nonce = nonces[packet.index];
    try {
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
