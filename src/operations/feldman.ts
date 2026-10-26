import { Point, Group } from '../backend';
import { InvalidSecretShare } from '../errors';
import { validateIndex } from '../indexes';
import { SecretShare, SecretPacket } from '../types';

import { ShamirSharing } from './shamir';
import { evalCommitments } from './commitments';


/** Feldman commitments and one packet per secret share; takes no ctx, as the
 * sharing carries its group. Commitments always number `threshold`: a vanished
 * top coefficient commits to the neutral element */
export async function createFeldmanPackets<P extends Point>(
  sharing: ShamirSharing<P>,
): Promise<{
  /** One per share, to be sent privately to its shareholder */
  packets: SecretPacket[],
  /** The generator raised to each coefficient of the sharing polynomial, to be
   * broadcast; the first is the public counterpart of the secret */
  commitments: Uint8Array[],
}> {
  const { expSecret, generator: g } = sharing.ctx;
  const { coeffs } = sharing.polynomial;
  const commitments = [];
  for (let i = 0; i < sharing.threshold; i++) {
    commitments.push((await expSecret(g, coeffs[i] ?? 0n)).toBytes());
  }
  const packets = await sharing.getSecretShares();
  return { packets, commitments };
}


/** Verify a secret share against Feldman commitments of a
 * `threshold`-sharing; returns true or throws InvalidSecretShare if the share
 * does not match or the commitments do not number `threshold`, and
 * InvalidInput on malformed input */
export async function verifyFeldmanCommitments<P extends Point>(
  ctx: Group<P>,
  commitments: Uint8Array[],
  share: SecretShare,
  threshold: number,
): Promise<boolean> {
  const { value, index } = share;
  validateIndex(index);
  const x = await ctx.parseScalar(value);
  const g = ctx.generator;
  const lhs = await ctx.expSecret(g, x);
  const rhs = await evalCommitments(ctx, commitments, index, threshold);
  const isValid = await lhs.equals(rhs);
  if (!isValid) throw new InvalidSecretShare(
    `Invalid share at index ${index}`
  );
  return true;
}


/** Extract the secret share of a Feldman packet, verified as by
 * {@link verifyFeldmanCommitments}, which throws on failure */
export async function parseFeldmanPacket<P extends Point>(
  ctx: Group<P>,
  commitments: Uint8Array[],
  packet: SecretPacket,
  threshold: number,
): Promise<{
  /** The verified share */
  share: SecretShare,
}> {
  const { value, index } = packet;
  const share = { value, index };
  await verifyFeldmanCommitments(ctx, commitments, share, threshold);
  return { share };
}
