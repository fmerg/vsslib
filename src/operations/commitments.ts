import { Point, Group } from '../backend';
import { InvalidSecretShare } from '../errors';
import { validateThreshold } from '../indexes';


/** Evaluate `Π_j C_j ^ (index ^ j)` in the exponent using Horner's rule,
 * ensuring that there is one commitment per coefficient of a `threshold`-sharing.
 * Every step raises to the index, which is public and small, so that the
 * variable-time `expPublic` costs a few doublings per step */
export async function evalCommitments<P extends Point>(
  ctx: Group<P>,
  commitments: Uint8Array[],
  index: number,
  threshold: number,
): Promise<P> {
  validateThreshold(threshold);
  if (commitments.length !== threshold) throw new InvalidSecretShare(
    `Invalid number of commitments: expected ${threshold}, got ${commitments.length}`
  );
  const x = BigInt(index);
  let acc = ctx.neutral;
  for (let j = commitments.length - 1; j >= 0; j--) {
    const c = await ctx.parsePoint(commitments[j]);
    acc = await ctx.operate(await ctx.expPublic(acc, x), c);
  }
  return acc;
}
