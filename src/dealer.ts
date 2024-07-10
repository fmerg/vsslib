import { Point, Group } from 'vsslib/backend';
import { mod, modInv } from 'vsslib/arith';
import { FieldPolynomial, randomPolynomial } from 'vsslib/polynomials';
import {
  InterpolationError,
  ShamirError,
  InvalidSecretShare,
  InvalidPublicShare,
} from 'vsslib/errors';
import { leInt2Buff } from 'vsslib/arith';
import { validateSecret, extractPublic } from 'vsslib/secrets';
import { NizkProof } from 'vsslib/nizk';
import { Algorithm } from 'vsslib/types';
import { Algorithms } from 'vsslib/enums';

import nizk from 'vsslib/nizk';
import lagrange from 'vsslib/lagrange';

const __0n = BigInt(0);
const __1n = BigInt(1);

export type SecretShare = { value: Uint8Array, index: number };
export type SecretPacket = SecretShare & { binding?: Uint8Array };

export type PublicShare = { value: Uint8Array, index: number };
export type ScnorrPacket = PublicShare & { proof: NizkProof };


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
    polynomial = await lagrange(ctx).interpolate(xyPoints);
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
    const polynomial = this.polynomial;
    const shares = new Array(this.nrShares);
    for (let index = 1; index <= this.nrShares; index++) {
      const value = leInt2Buff(polynomial.evaluate(index));
      shares[index - 1] = { value, index };
    }
    return shares;
  }

  getPublicShares = async (): Promise<PublicShare[]> => {
    const polynomial = this.polynomial;
    const shares = [];
    const g = this.ctx.generator;
    for (let index = 1; index <= this.nrShares; index++) {
      const x = polynomial.evaluate(index);
      const y = await this.ctx.exp(g, x);
      const value = y.toBytes();
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
    const polynomial = this.polynomial;
    const degree = polynomial.degree;
    const g = this.ctx.generator;
    const h = await this.ctx.unpackValid(publicBytes);
    const exp = this.ctx.exp;
    const commitments = new Array(degree + 1);
    const bindings = new Array(degree + 1);
    const packets = new Array<SecretPacket>(this.nrShares);
    const bindingPolynomial = await randomPolynomial(this.ctx, degree);
    for (let i = 0; i < this.nrShares; i++) {
      if (i < degree + 1) {
        const a = polynomial.coeffs[i];
        const b = bindingPolynomial.coeffs[i];
        const c = await this.ctx.operate(
          await exp(g, a),
          await exp(h, b),
        );
        commitments[i] = c.toBytes();
      }
      const index = i + 1;
      const x = polynomial.evaluate(index);
      const s = bindingPolynomial.evaluate(index)
      const value = leInt2Buff(x);
      const binding = leInt2Buff(s);
      bindings[i] = binding;
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
  const x = ctx.leBuff2Scalar(share.value);
  const g = ctx.generator;
  const order = ctx.order;
  const lhs = await ctx.exp(g, x);
  let rhs = ctx.neutral;
  for (const [j, commitment] of commitments.entries()) {
    const c = await ctx.unpackValid(commitment);
    const curr = await ctx.exp(c, mod(BigInt(index ** j), order));
    rhs = await ctx.operate(rhs, curr);
  }
  const isValid = await lhs.equals(rhs);
  if (!isValid) throw new InvalidSecretShare(
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
  const { value, index } = share;
  const exp = ctx.exp;
  const order = ctx.order;
  const g = ctx.generator;
  const h = await ctx.unpackValid(publicBytes);
  const x = ctx.leBuff2Scalar(value);
  const s = ctx.leBuff2Scalar(binding);
  const lhs = await ctx.operate(
    await exp(g, x),
    await exp(h, s)
  );
  let rhs = ctx.neutral;
  for (const [j, commitment] of commitments.entries()) {
    const c = await ctx.unpackValid(commitment);
    const curr = await exp(c, mod(BigInt(index ** j), order));
    rhs = await ctx.operate(rhs, curr);
  }
  const isValid = await lhs.equals(rhs);
  if (!isValid) throw new InvalidSecretShare(
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


export async function createScnorrPacket<P extends Point>(
  ctx: Group<P>,
  share: SecretShare,
  opts?: { algorithm?: Algorithm, nonce?: Uint8Array },
): Promise<ScnorrPacket> {
  const { value, index } = share;
  const g = ctx.generator;
  const algorithm = opts ? (opts.algorithm || Algorithms.DEFAULT) : Algorithms.DEFAULT;
  const nonce = opts ? (opts.nonce || undefined) : undefined;
  const x = ctx.leBuff2Scalar(value);
  const y = await ctx.exp(g, x);
  const proof = await nizk(ctx, algorithm).proveDlog(x, { u: g, v: y }, nonce);
  return { value: y.toBytes(), index, proof };
}


export async function parseScnorrPacket<P extends Point>(
  ctx: Group<P>,
  packet: ScnorrPacket,
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
