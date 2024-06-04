import { Point, Group } from '../backend/abstract';
import { mod, modInv } from '../arith';
import { FieldPolynomial } from '../lagrange/utils';
import { ErrorMessages } from '../errors';
import { randomPolynomial } from '../lagrange/utils';
import { leInt2Buff } from '../arith';
import { NizkProof } from '../nizk';
import { Algorithm } from '../types';
import { Algorithms } from '../enums';
import nizk from '../nizk';

const lagrange = require('../lagrange');

const __0n = BigInt(0);
const __1n = BigInt(1);

export type SecretShare = { value: Uint8Array, index: number };
export type SecretSharePacket = SecretShare & { binding?: Uint8Array };
export type PublicShare = { value: Uint8Array, index: number };
export type PublicSharePacket = PublicShare & { proof: NizkProof };


export async function shareSecret<P extends Point>(
  ctx: Group<P>,
  nrShares: number,
  threshold: number,
  secret: Uint8Array,
  predefined?: [bigint, bigint][]
): Promise<ShamirSharing<P>> {
  predefined = predefined || [];

  if (nrShares < 1)
    throw new Error(ErrorMessages.NR_SHARES_BELOW_ONE);
  if (threshold < 1)
    throw new Error(ErrorMessages.THRESHOLD_BELOW_ONE);
  if (threshold > nrShares)
    throw new Error(ErrorMessages.THRESHOLD_EXCEEDS_NR_SHARES);
  if (!(nrShares < ctx.order))
    throw new Error(ErrorMessages.NR_SHARES_VIOLATES_ORDER);
  if (!(predefined.length < threshold))
    throw new Error(ErrorMessages.NR_PREDEFINED_VIOLATES_THRESHOLD);

  const xyPoints = new Array(threshold);
  xyPoints[0] = [__0n, ctx.leBuff2Scalar(secret)];
  let index = 1;
  while (index < threshold) {
    const x = index;
    const y = index > predefined.length ? await ctx.randomScalar() : predefined[index - 1];
    xyPoints[index] = [x, y];
    index++;
  }
  const polynomial = await lagrange.interpolate(ctx, xyPoints);
  return new ShamirSharing(ctx, nrShares, threshold, polynomial);
}


export class ShamirSharing<P extends Point> {
  ctx: Group<P>;
  nrShares: number;
  threshold: number;
  polynomial: FieldPolynomial<P>;

  constructor(
    ctx: Group<P>, nrShares: number, threshold: number, polynomial: FieldPolynomial<P>
  ) {
    this.ctx = ctx;
    this.threshold = threshold;
    this.nrShares = nrShares;
    this.polynomial = polynomial;
  }

  getSecretShares = async (): Promise<SecretShare[]> => {
    const { polynomial: { evaluate }, nrShares } = this;
    const shares = new Array(nrShares);
    for (let index = 1; index <= nrShares; index++) {
      const value = leInt2Buff(evaluate(index));
      shares[index - 1] = { value, index };
    }
    return shares;
  }

  getPublicShares = async (): Promise<PublicShare[]> => {
    const { nrShares, polynomial: { evaluate }, ctx: { exp, generator } } = this;
    const shares = [];
    for (let index = 1; index <= nrShares; index++) {
      const aux = await exp(evaluate(index), generator);
      const value = aux.toBytes();
      shares.push({ value, index });
    }
    return shares;
  }

  createFeldmannPackets = async (): Promise<{
    packets: SecretSharePacket[],
    commitments: Uint8Array[],
  }> => {
    const { exp, generator: g } = this.ctx;
    const { coeffs, degree, evaluate } = this.polynomial;
    const commitments = new Array(degree + 1);
    const packets = new Array<SecretSharePacket>(this.nrShares);
    for (let i = 0; i < this.nrShares; i++) {
      if (i < degree + 1) {
        const c = await exp(coeffs[i], g);
        commitments[i] = c.toBytes();
      }
      const index = i + 1;
      const value = leInt2Buff(evaluate(index));
      packets[i] = { value, index };
    }
    return { packets, commitments };
  }

  createPedersenPackets = async (publicBytes: Uint8Array): Promise<{
    packets: SecretSharePacket[],
    bindings: Uint8Array[],
    commitments: Uint8Array[],
  }> => {
    const { operate, exp, generator: g } = this.ctx;
    const { coeffs, degree, evaluate } = this.polynomial;
    const h = await this.ctx.unpackValid(publicBytes);
    const commitments = new Array(degree + 1);
    const bindings = new Array(degree + 1);
    const packets = new Array<SecretSharePacket>(this.nrShares);
    const bindingPolynomial = await randomPolynomial(this.ctx, degree);
    for (let i = 0; i < this.nrShares; i++) {
      if (i < degree + 1) {
        const a = coeffs[i];
        const b = bindingPolynomial.coeffs[i];
        const c = await operate(
          await exp(a, g),
          await exp(b, h),
        );
        commitments[i] = c.toBytes();
      }
      const index = i + 1;
      const binding = leInt2Buff(bindingPolynomial.evaluate(index));
      bindings[i] = binding;
      const value = leInt2Buff(evaluate(index));
      packets[i] = { value, index, binding };
    }
    return { packets, bindings, commitments };
  }
};


export async function verifyFeldmannCommitments<P extends Point>(
  ctx: Group<P>,
  share: SecretShare,
  commitments: Uint8Array[],
): Promise<boolean> {
  const { value, index } = share;
  const { order, generator: g, neutral, exp, operate } = ctx;
  const lhs = await exp(ctx.leBuff2Scalar(value), g);
  let rhs = neutral;
  for (const [j, commitment] of commitments.entries()) {
    const c = await ctx.unpackValid(commitment);
    const curr = await exp(mod(BigInt(index ** j), order), c);
    rhs = await operate(rhs, curr);
  }
  const valid = await lhs.equals(rhs);
  if (!valid)
    throw new Error('Invalid share');
  return true;
}


export async function verifyPedersenCommitments<P extends Point>(
  ctx: Group<P>,
  share: SecretShare,
  binding: Uint8Array,
  publicBytes: Uint8Array,
  commitments: Uint8Array[],
): Promise<boolean> {
  const h = await ctx.unpackValid(publicBytes);
  const { value, index } = share;
  const { order, generator: g, neutral, exp, operate } = ctx;
  const s = ctx.leBuff2Scalar(value);
  const b = ctx.leBuff2Scalar(binding);
  const lhs = await operate(
    await exp(s, g),
    await exp(b, h)
  );
  let rhs = neutral;
  for (const [j, commitment] of commitments.entries()) {
    const c = await ctx.unpackValid(commitment);
    rhs = await operate(rhs, await exp(BigInt(index ** j), c));
  }
  const valid = await lhs.equals(rhs);
  if (!valid)
    throw new Error('Invalid share');
  return true;
}


export async function parseFeldmannPacket<P extends Point>(
  ctx: Group<P>,
  commitments: Uint8Array[],
  packet: SecretSharePacket,
): Promise<SecretShare> {
  const { value, index } = packet;
  const share = { value, index };
  await verifyFeldmannCommitments(ctx, share, commitments);
  return share;
}


export async function parsePedersenPacket<P extends Point>(
  ctx: Group<P>,
  commitments: Uint8Array[],
  publicBytes: Uint8Array,
  packet: SecretSharePacket,
): Promise<{ share: SecretShare, binding: Uint8Array }> {
  const { value, index, binding } = packet;
  if (!binding) {
    throw new Error('No binding found');
  }
  const share = { value, index }
  const verified = await verifyPedersenCommitments(
    ctx, share, binding, publicBytes, commitments,
  );
  return { share, binding };
}


export async function createPublicSharePacket<P extends Point>(
  ctx: Group<P>,
  share: SecretShare,
  opts?: { algorithm?: Algorithm, nonce?: Uint8Array },
): Promise<PublicSharePacket> {
  const { value, index } = share;
  const g = ctx.generator;
  const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
  const nonce = opts ? (opts.nonce || undefined) : undefined;
  const x = ctx.leBuff2Scalar(value);
  const y = await ctx.exp(x, g);
  const proof = await nizk(ctx, algorithm).proveDlog(x, { u: g, v: y }, nonce);
  return { value: y.toBytes(), index, proof };
}


export async function parsePublicSharePacket<P extends Point>(
  ctx: Group<P>,
  packet: PublicSharePacket,
  opts?: {
    algorithm?: Algorithm,
    nonce?: Uint8Array,
  },
): Promise<PublicShare> {
  const { value, index, proof } = packet;
  const y = await ctx.unpackValid(value);
  const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
  const nonce = opts ? (opts.nonce || undefined) : undefined;
  const verified = await nizk(ctx, algorithm).verifyDlog(
    {
      u: ctx.generator,
      v: y,
    },
    proof,
    nonce
  );
  if (!verified)
    throw new Error("Invalid public share");
  return { value, index };
}


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


export function reconstructSecret<P extends Point>(
  ctx: Group<P>,
  shares: SecretShare[]
): Uint8Array {
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


export async function reconstructPublic<P extends Point>(
  ctx: Group<P>,
  shares: PublicShare[]
): Promise<Uint8Array> {
  const { order, operate, neutral, exp, unpackValid } = ctx;
  const indexes = shares.map(share => share.index);
  let acc = neutral;
  for (const { index, value } of shares) {
    const lambda = computeLambda(ctx, index, indexes);
    const curr = await unpackValid(value);
    acc = await operate(acc, await exp(lambda, curr));
  }
  return acc.toBytes();
}
