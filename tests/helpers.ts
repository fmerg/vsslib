import { Group, Point } from '../src/backend/abstract';
import { initBackend } from '../src/backend';
import { generateKey } from '../src';
import { ElgamalSchemes } from '../src/enums';
import { ElgamalScheme, System, Algorithm } from '../src/types';
import { distributeSecret, createPublicPacket, SecretShare, PublicShare } from '../src/dealer';
import { PartialKey, PartialPublic } from '../src/keys';
import { leInt2Buff } from '../src/arith';
import { randomIndex } from './utils';

export async function randomDlogPair<P extends Point>(ctx: Group<P>): Promise<{
  x: bigint, y: P, secret: Uint8Array, publicBytes: Uint8Array
}> {
  const { randomScalar, exp, generator: g } = ctx;
  const x = await randomScalar();
  const y = await exp(g, x);
  return { x, y, secret: leInt2Buff(x), publicBytes: y.toBytes() };
}

/** Check equality of byte arrays as secret scalars **/
export const isEqualSecret = (
  ctx: Group<Point>,
  lhs: Uint8Array,
  rhs: Uint8Array,
): boolean => ctx.leBuff2Scalar(lhs) == ctx.leBuff2Scalar(rhs);

export const buildMessage = async (ctx: Group<Point>, scheme: ElgamalScheme) =>
  scheme == ElgamalSchemes.PLAIN ? await ctx.randomPublic() :
    Uint8Array.from(Buffer.from('destroy earth'));

export const selectSecretShare = (index: number, shares: SecretShare[]): SecretShare =>
  shares.filter(share => share.index == index)[0];

export const selectPublicShare = (index: number, shares: PublicShare[]): PublicShare =>
  shares.filter(share => share.index == index)[0];

export const selectPartialKey = (index: number, shares: PartialKey<Point>[]) =>
  shares.filter(share => share.index == index)[0];

export const selectPartialPublic = (index: number, shares: PartialPublic<Point>[]) =>
  shares.filter(share => share.index == index)[0];


export const createSharingSetup = async (opts: {
  system: System,
  nrShares: number,
  threshold: number,
}) => {
  const { system, nrShares, threshold } = opts;
  const ctx = initBackend(system);
  const { secret, publicBytes } = await randomDlogPair(ctx);
  const { sharing } = await distributeSecret(ctx, nrShares, threshold, secret);
  const secretShares = await sharing.getSecretShares();
  const publicShares = await sharing.getPublicShares();
  return { ctx, secret, publicBytes, sharing, secretShares, publicShares };
}


export const createPublicPackets = async (opts: {
  ctx: Group<Point>,
  shares: SecretShare[],
  algorithm?: Algorithm,
  nrInvalidIndexes?: number,
}) => {
  let { ctx, shares, algorithm, nrInvalidIndexes } = opts;
  const packets = [];
  for (const share of shares) {
    const packet = await createPublicPacket(ctx, share, { algorithm });
    packets.push(packet);
  }
  let blame: number[] = [];
  nrInvalidIndexes = nrInvalidIndexes || 0;
  while (blame.length < nrInvalidIndexes) {
    const index = randomIndex(1, shares.length);
    if (blame.includes(index)) continue;
    blame.push(index);
  }
  const invalidPackets = [];
  if (blame) {
    for (const packet of packets) {
      invalidPackets.push(!(blame.includes(packet.index)) ? packet : {
        value: await ctx.randomPublic(),
        index: packet.index,
        proof: packet.proof,
      });
    }
  }
  return { packets, invalidPackets, blame };
}


export const createKeySharingSetup = async (opts: {
  system: System,
  nrShares: number,
  threshold: number,
}) => {
  const { system, nrShares, threshold } = opts;
  const ctx = initBackend(system)
  const { privateKey, publicKey } = await generateKey(ctx);
  const sharing = await privateKey.generateSharing(nrShares, threshold);
  const polynomial = sharing.polynomial;
  const secretShares = await sharing.getSecretShares();
  const privateShares = secretShares.map(({ value, index }: SecretShare) => {
    return new PartialKey(ctx, value, index);
  });
  const publicShares = []
  for (const share of privateShares) {
    publicShares.push(await share.getPublicShare());
  }
  return {
    ctx,
    privateKey,
    publicKey,
    sharing,
    polynomial,
    privateShares,
    publicShares,
  };
}


export const createThresholdDecryptionSetup = async (opts: {
  system: System,
  scheme: ElgamalScheme,
  nrShares: number,
  threshold: number,
  nrInvalidIndexes?: number,
}) => {
  let { scheme, system, nrShares, threshold, nrInvalidIndexes } = opts;
  const {
    privateKey,
    publicKey,
    privateShares,
    publicShares,
    ctx,
  } = await createKeySharingSetup({ system, nrShares, threshold, });
  const message = await buildMessage(ctx, scheme);
  const { ciphertext, decryptor } = await publicKey.encrypt(message, { scheme });
  const partialDecryptors = [];
  for (const privateShare of privateShares) {
    const share = await privateShare.computePartialDecryptor(ciphertext);
    partialDecryptors.push(share);
  }
  let blame: number[] = [];
  nrInvalidIndexes = nrInvalidIndexes || 0;
  while (blame.length < nrInvalidIndexes) {
    const index = randomIndex(1, nrShares);
    if (blame.includes(index)) continue;
    blame.push(index);
  }
  const invalidDecryptors = [];
  if (blame) {
    for (const share of partialDecryptors) {
      invalidDecryptors.push(!(blame.includes(share.index)) ? share : {
        value: await ctx.randomPublic(),
        index: share.index,
        proof: share.proof,
      });
    }
  }
  return {
    ctx,
    privateKey,
    publicKey,
    privateShares,
    publicShares,
    message,
    ciphertext,
    decryptor,
    partialDecryptors,
    invalidDecryptors,
    blame,
  }
}
