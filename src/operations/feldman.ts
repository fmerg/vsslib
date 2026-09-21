import { Point, Group } from '../backend';
import { InvalidSecretShare } from '../errors';
import { validateIndex } from '../indexes';
import { SecretShare, SecretPacket } from '../types';

import { ShamirSharing } from './shamir';
import { evalCommitments } from './commitments';


/** Feldman commitments and one packet per secret share; takes no ctx, as the
 * sharing carries its group */
export async function createFeldmanPackets<P extends Point>(
  sharing: ShamirSharing<P>,
): Promise<{ packets: SecretPacket[], commitments: Uint8Array[] }> {
  const { expSecret, generator: g } = sharing.ctx;
  const commitments = [];
  for (const a of sharing.polynomial.coeffs) {
    commitments.push((await expSecret(g, a)).toBytes());
  }
  const packets = await sharing.getSecretShares();
  return { packets, commitments };
}


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


export async function parseFeldmanPacket<P extends Point>(
  ctx: Group<P>,
  commitments: Uint8Array[],
  packet: SecretPacket,
  threshold: number,
): Promise<{ share: SecretShare }> {
  const { value, index } = packet;
  const share = { value, index };
  await verifyFeldmanCommitments(ctx, commitments, share, threshold);
  return { share };
}
