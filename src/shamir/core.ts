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


export type PointShare<P extends Point> = { value: P, index: number };

export class SecretShare<P extends Point> {
  ctx: Group<P>;
  value: bigint;
  index: number;

  constructor(ctx: Group<P>, value: bigint, index: number) {
    this.ctx = ctx;
    this.value = value;
    this.index = index;
  }

  verifyFeldmann = async (commitments: P[]): Promise<boolean> => {
    const { value: secret, index } = this;
    const { order, generator, neutral, exp, operate } = this.ctx;
    const lhs = await exp(secret, generator);
    let rhs = neutral;
    for (const [j, c] of commitments.entries()) {
      const curr = await exp(mod(BigInt(index ** j), order), c);
      rhs = await operate(rhs, curr);
    }
    return lhs.equals(rhs);
  }

  verifyPedersen = async (binding: bigint, pub: P, commitments: P[]): Promise<boolean> => {
    const h = pub;
    const { value: secret, index } = this;
    const { order, generator: g, neutral, exp, operate } = this.ctx;
    const lhs = await operate(
      await exp(secret, g),
      await exp(binding, h)
    );
    let rhs = neutral;
    for (const [j, c] of commitments.entries()) {
      rhs = await operate(rhs, await exp(BigInt(index ** j), c));
    }
    return lhs.equals(rhs);
  }
};


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

  getSecretShares = async (): Promise<SecretShare<P>[]> => {
    const { polynomial: { evaluate }, nrShares } = this;
    const shares = new Array(nrShares);
    for (let index = 1; index <= nrShares; index++) {
      shares[index - 1] = new SecretShare(this.ctx, evaluate(index), index);
    }
    return shares;
  }

  getPointShares = async (): Promise<PointShare<P>[]> => {
    const { nrShares, polynomial: { evaluate }, ctx: { exp, generator } } = this;
    const shares = [];
    for (let index = 1; index <= nrShares; index++) {
      const value = await exp(evaluate(index), generator);
      shares.push({ value, index });
    }
    return shares;
  }

  getSecretShare = async (index: number): Promise<SecretShare<P>> => {
    if (index < 1 || index > this.nrShares)
      throw new Error('Invalid index');
    const value = this.polynomial.evaluate(index);
    return new SecretShare(this.ctx, value, index);
  }

  proveFeldmann = async (): Promise<{ commitments: P[] }> => {
    const { coeffs, degree, ctx: { exp, generator }} = this.polynomial;
    const commitments = new Array(degree + 1);
    for (const [index, coeff] of coeffs.entries()) {
      commitments[index] = await exp(coeff, generator);
    }
    return { commitments };
  }

  provePedersen = async (pub: P): Promise<{
    commitments: P[],
    bindings: bigint[],
  }> => {
    const h = pub;
    const { generator: g, operate, exp } = this.ctx;
    const { coeffs, degree } = this.polynomial;
    const bindingPolynomial = await randomPolynomial(this.ctx, degree);
    const commitments = new Array(degree + 1);
    const bindings = new Array(degree + 1);
    for (const [i, a] of coeffs.entries()) {
      const a = coeffs[i];
      const b = bindingPolynomial.coeffs[i];
      commitments[i] = await operate(
        await exp(a, g),
        await exp(b, h),
      );
      bindings[i] = await bindingPolynomial.evaluate(i);
    }
    for (let j = coeffs.length; j <= this.nrShares; j++) {
      bindings[j] = await bindingPolynomial.evaluate(j);
    }
    return { commitments, bindings };
  }

  createFeldmannPackets = async (): Promise<{
    packets: SharePacket[],
    commitments: Uint8Array[],
  }> => {
    const packets = [];
    const { commitments: innerCommitments } = await this.proveFeldmann();
    const commitments = innerCommitments.map(c => c.toBytes()); // TODO
    for (let index = 1; index <= this.nrShares; index++) {
      const share = await this.getSecretShare(index);
      const value = leInt2Buff(share.value);
      packets.push({ value, index });
    }
    return { packets, commitments };
  }

  createPedersenPackets = async (publicBytes: Uint8Array): Promise<{
    packets: SharePacket[],
    commitments: Uint8Array[],
  }> => {
    const packets = [];
    const pub = await this.ctx.unpackValid(publicBytes);
    const {
      commitments: innerCommitments,
      bindings: innerBindings,
    } = await this.provePedersen(pub);
    const commitments = innerCommitments.map(c => c.toBytes()); // TODO
    const bindings = innerBindings.map(b => leInt2Buff(b)); // TODO
    for (let index = 1; index <= this.nrShares; index++) {
      const share = await this.getSecretShare(index);
      const value = leInt2Buff(share.value);
      const binding = bindings[index]
      packets.push({ value, index, binding });
    }
    return { packets, commitments };
  }
};

export type SharePacket = {
  value: Uint8Array,
  index: number,
  binding?: Uint8Array,
}

export type PublicSharePacket = {
  value: Uint8Array,
  index: number,
  proof: NizkProof,
}


export async function verifyFeldmann<P extends Point>(
  ctx: Group<P>,
  share: SecretShare<P>,
  commitments: P[],
): Promise<boolean> {
  const { value: secret, index } = share;
  const { order, generator, neutral, exp, operate } = ctx;
  const lhs = await exp(secret, generator);
  let rhs = neutral;
  for (const [j, c] of commitments.entries()) {
    const curr = await exp(mod(BigInt(index ** j), order), c);
    rhs = await operate(rhs, curr);
  }
  return lhs.equals(rhs);
}

export async function verifyPedersen<P extends Point>(
  ctx: Group<P>,
  share: SecretShare<P>,
  binding: bigint,
  pub: P,
  commitments: P[]
): Promise<boolean> {
  const h = pub;
  const { value: secret, index } = share;
  const { order, generator: g, neutral, exp, operate } = ctx;
  const lhs = await operate(
    await exp(secret, g),
    await exp(binding, h)
  );
  let rhs = neutral;
  for (const [j, c] of commitments.entries()) {
    rhs = await operate(rhs, await exp(BigInt(index ** j), c));
  }
  return lhs.equals(rhs);
}

export async function parseFeldmannPacket<P extends Point>(
  ctx: Group<P>,
  commitments: Uint8Array[],
  packet: SharePacket,
): Promise<SecretShare<P>> {
  const { value: bytes, index } = packet;
  const value = ctx.leBuff2Scalar(bytes);
  const share = new SecretShare(ctx, value, index);
  const innerCommitments = new Array(commitments.length);
  // TODO: avoid this loop?
  for (let i = 0; i < commitments.length; i++) {
    innerCommitments[i] = await ctx.unpackValid(commitments[i]);
  }
  const verified = await verifyFeldmann(ctx, share, innerCommitments);
  if (!verified) {
    throw new Error("Invalid share");
  }
  return share;
}


export async function parsePedersenPacket<P extends Point>(
  ctx: Group<P>,
  commitments: Uint8Array[],
  publicBytes: Uint8Array,
  packet: SharePacket,
): Promise<{ share: SecretShare<P>, binding: bigint }> {
  const { value: bytes, index, binding } = packet;
  if (!binding) {
    throw new Error('No binding found');
  }
  const value = ctx.leBuff2Scalar(bytes);
  const share = new SecretShare(ctx, value, index);
  const innerCommitments = new Array(commitments.length);
  // TODO: avoid this loop?
  for (let i = 0; i < commitments.length; i++) {
    innerCommitments[i] = await ctx.unpackValid(commitments[i]);
  }
  // TODO: Avoid this
  const innerBinding = ctx.leBuff2Scalar(binding);
  const innerPublic  = await ctx.unpackValid(publicBytes);
  const verified = await verifyPedersen(
    ctx, share, innerBinding, innerPublic, innerCommitments
  );
  if (!verified) {
    throw new Error("Invalid share");
  }
  return { share, binding: innerBinding };
}

export async function createPublicSharePacket<P extends Point>(
  share: SecretShare<P>,
  opts?: { algorithm?: Algorithm, nonce?: Uint8Array },
): Promise<PublicSharePacket> {
  const { ctx, value: x, index } = share;
  const g = ctx.generator;
  const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
  const nonce = opts ? (opts.nonce || undefined) : undefined;
  const y = await ctx.exp(x, g);
  const proof = await nizk(ctx, algorithm).proveDlog(x, { u: ctx.generator, v: y }, nonce);
  return { value: y.toBytes(), index, proof };
}

export async function parsePublicSharePacket<P extends Point>(
  ctx: Group<P>,
  packet: PublicSharePacket,
  opts?: {
    algorithm?: Algorithm,
    nonce?: Uint8Array,
  },
): Promise<PointShare<P>> {
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
  return { value: y, index };
}


export async function shareSecret<P extends Point>(
  ctx: Group<P>,
  nrShares: number,
  threshold: number,
  secret: bigint,
  predefined?: [bigint, bigint][]
): Promise<ShamirSharing<P>> {
  predefined = predefined || [];
  if (nrShares < 1) throw new Error(ErrorMessages.NR_SHARES_BELOW_ONE);
  if (threshold < 1) throw new Error(ErrorMessages.THRESHOLD_BELOW_ONE);
  if (threshold > nrShares) throw new Error(ErrorMessages.THRESHOLD_EXCEEDS_NR_SHARES);
  if (!(nrShares < ctx.order)) throw new Error(ErrorMessages.NR_SHARES_VIOLATES_ORDER);
  if (!(predefined.length < threshold)) throw new Error(
    ErrorMessages.NR_PREDEFINED_VIOLATES_THRESHOLD
  );
  const xyPoints = new Array(threshold);
  xyPoints[0] = [__0n, secret];
  let index = 1;
  while (index < threshold) {
    const x = index;
    const y = index <= predefined.length ? predefined[index - 1] :
      await ctx.randomScalar();
    xyPoints[index] = [x, y];
    index++;
  }
  const polynomial = await lagrange.interpolate(ctx, xyPoints);
  return new ShamirSharing<P>(ctx, nrShares, threshold, polynomial);
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
  qualifiedShares: SecretShare<P>[]
): bigint {
  const { order } = ctx;
  const indexes = qualifiedShares.map(share => share.index);
  return qualifiedShares.reduce(
    (acc, { value, index }) => {
      const lambda = computeLambda(ctx, index, indexes);
      return mod(acc + value * lambda, order);
    },
    __0n
  );
}


export async function reconstructPoint<P extends Point>(
  ctx: Group<P>,
  qualifiedShares: PointShare<P>[]
): Promise<P> {
  const { order, operate, neutral, exp } = ctx;
  const indexes = qualifiedShares.map(share => share.index);
  let acc = neutral;
  for (const { index, value } of qualifiedShares) {
    const lambda = computeLambda(ctx, index, indexes);
    acc = await operate(acc, await exp(lambda, value));
  }
  return acc;
}
