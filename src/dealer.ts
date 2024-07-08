import { Point, Group } from './backend';
import { mod, modInv } from './arith';
import { FieldPolynomial, randomPolynomial } from './polynomials';
import {
  InterpolationError,
  ShamirError,
  InvalidSecretShare,
  InvalidPublicShare,
} from './errors';
import { leInt2Buff } from './arith';
import { validateSecret, extractPublic } from './secrets';
import { NizkProof } from './nizk';
import { Algorithm } from './types';
import { Algorithms } from './enums';
import nizk from './nizk';

const lagrange = require('./lagrange');

const __0n = BigInt(0);
const __1n = BigInt(1);

export type SecretShare = { value: Uint8Array, index: number };
export type SecretPacket = SecretShare & { binding?: Uint8Array };

export type PublicShare = { value: Uint8Array, index: number };
export type PublicPacket = PublicShare & { proof: NizkProof };


export async function extractPublicShare<P extends Point>(
  ctx: Group<P>, share: SecretShare
): Promise<PublicShare> {
  const { value: secret, index } = share;
  return { value: await extractPublic(ctx, secret), index };
}


export async function distributeSecret<P extends Point>(
  ctx: Group<P>, nrShares: number, threshold: number, secret?: Uint8Array, predefined?: Uint8Array[]
): Promise<{ secret: Uint8Array, sharing: ShamirSharing<P>}> {
  predefined = predefined || [];
  if (nrShares < 1) throw new ShamirError(
    `Number of shares must be at least one: ${nrShares}`
  );
  if (threshold < 1) throw new ShamirError(
    `Threshold parameter must be at least 1: ${threshold}`
  );
  if (threshold > nrShares) throw new ShamirError(
    `Threshold parameter exceeds number of shares: ${threshold} > ${nrShares}`
  );
  if (!(nrShares < ctx.order)) throw new ShamirError(
    `Number of shares violates the group order: ${nrShares} >= ${ctx.order}`
  );
  if (!(predefined.length < threshold)) throw new ShamirError(
    `Number of predefined shares violates threshold: ${predefined.length} >= ${threshold}`,
  );

  secret = secret || await ctx.randomSecret()
  try {
    await validateSecret(ctx, secret);
  } catch (err) {
    throw new Error('Invalid secret provided');
  }
  const xyPoints = new Array(threshold);
  xyPoints[0] = [__0n, ctx.leBuff2Scalar(secret)];
  let index = 1;
  while (index < threshold) {
    const x = index;
    const y = index > predefined.length ? await ctx.randomScalar() :
      ctx.leBuff2Scalar(predefined[index - 1]);
    xyPoints[index] = [x, y];
    index++;
  }

  let polynomial;
  try {
    polynomial = await lagrange.interpolate(ctx, xyPoints);
  } catch (err: any) {
    if (err instanceof InterpolationError) throw new ShamirError(
      err.message
    );
    else throw err;
  }
  const sharing = new ShamirSharing(ctx, nrShares, threshold, polynomial);
  return { secret, sharing };
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

  getOriginalSecret = (): Uint8Array => {
    return leInt2Buff(this.polynomial.evaluate(__0n));
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
      const aux = await exp(generator, evaluate(index));
      const value = aux.toBytes();
      shares.push({ value, index });
    }
    return shares;
  }

  getShare = async (index: number): Promise<{
    secretShare: SecretShare,
    publicShare: PublicShare
  }> => {
    const g = this.ctx.generator;
    const x = await this.polynomial.evaluate(index);
    const y = await this.ctx.exp(g, x);
    return {
      secretShare: {
        value: leInt2Buff(x),
        index,
      },
      publicShare: {
        value: y.toBytes(),
        index,
      }
    };
  }

  createFeldmanPackets = async (): Promise<{
    packets: SecretPacket[],
    commitments: Uint8Array[],
  }> => {
    const { exp, generator: g } = this.ctx;
    const { coeffs, degree, evaluate } = this.polynomial;
    const commitments = new Array(degree + 1);
    const packets = new Array<SecretPacket>(this.nrShares);
    for (let i = 0; i < this.nrShares; i++) {
      if (i < degree + 1) {
        const c = await exp(g, coeffs[i]);
        commitments[i] = c.toBytes();
      }
      const index = i + 1;
      const value = leInt2Buff(evaluate(index));
      packets[i] = { value, index };
    }
    return { packets, commitments };
  }

  createPedersenPackets = async (publicBytes: Uint8Array): Promise<{
    packets: SecretPacket[],
    bindings: Uint8Array[],
    commitments: Uint8Array[],
  }> => {
    const { operate, exp, generator: g } = this.ctx;
    const { coeffs, degree, evaluate } = this.polynomial;
    const h = await this.ctx.unpackValid(publicBytes);
    const commitments = new Array(degree + 1);
    const bindings = new Array(degree + 1);
    const packets = new Array<SecretPacket>(this.nrShares);
    const bindingPolynomial = await randomPolynomial(this.ctx, degree);
    for (let i = 0; i < this.nrShares; i++) {
      if (i < degree + 1) {
        const a = coeffs[i];
        const b = bindingPolynomial.coeffs[i];
        const c = await operate(
          await exp(g, a),
          await exp(h, b),
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


export async function verifyFeldmanCommitments<P extends Point>(
  ctx: Group<P>,
  share: SecretShare,
  commitments: Uint8Array[],
): Promise<boolean> {
  const { value, index } = share;
  const { order, generator: g, neutral, exp, operate } = ctx;
  const lhs = await exp(g, ctx.leBuff2Scalar(value));
  let rhs = neutral;
  for (const [j, commitment] of commitments.entries()) {
    const c = await ctx.unpackValid(commitment);
    const curr = await exp(c, mod(BigInt(index ** j), order));
    rhs = await operate(rhs, curr);
  }
  const valid = await lhs.equals(rhs);
  if (!valid) throw new InvalidSecretShare(
    `Invalid share at index ${index}`
  );
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
    await exp(g, s),
    await exp(h, b)
  );
  let rhs = neutral;
  for (const [j, commitment] of commitments.entries()) {
    const c = await ctx.unpackValid(commitment);
    rhs = await operate(rhs, await exp(c, BigInt(index ** j)));
  }
  const valid = await lhs.equals(rhs);
  if (!valid) throw new InvalidSecretShare(
    `Invalid share at index ${index}`
  );
  return true;
}


export async function parseFeldmanPacket<P extends Point>(
  ctx: Group<P>,
  commitments: Uint8Array[],
  packet: SecretPacket,
): Promise<SecretShare> {
  const { value, index } = packet;
  const share = { value, index };
  await verifyFeldmanCommitments(ctx, share, commitments);
  return share;
}


export async function parsePedersenPacket<P extends Point>(
  ctx: Group<P>,
  commitments: Uint8Array[],
  publicBytes: Uint8Array,
  packet: SecretPacket,
): Promise<{ share: SecretShare, binding: Uint8Array }> {
  const { value, index, binding } = packet;
  if (!binding)
    throw new Error(
      `No binding found for index ${index}`
    );
  const share = { value, index }
  await verifyPedersenCommitments(
    ctx, share, binding, publicBytes, commitments,
  );
  return { share, binding };
}


export async function createPublicPacket<P extends Point>(
  ctx: Group<P>,
  share: SecretShare,
  opts?: { algorithm?: Algorithm, nonce?: Uint8Array },
): Promise<PublicPacket> {
  const { value, index } = share;
  const g = ctx.generator;
  const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
  const nonce = opts ? (opts.nonce || undefined) : undefined;
  const x = ctx.leBuff2Scalar(value);
  const y = await ctx.exp(g, x);
  const proof = await nizk(ctx, algorithm).proveDlog(x, { u: g, v: y }, nonce);
  return { value: y.toBytes(), index, proof };
}


export async function parsePublicPacket<P extends Point>(
  ctx: Group<P>,
  packet: PublicPacket,
  opts?: {
    algorithm?: Algorithm,
    nonce?: Uint8Array,
  },
): Promise<PublicShare> {
  const { value, index, proof } = packet;
  const y = await ctx.unpackValid(value);
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
