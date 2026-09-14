/** Shamir's Secret Sharing (SSS): a dealer splits a secret into n shares, of
 * which any t reconstruct the secret, or its public counterpart from the
 * respective public shares. Shares are not verifiable; see vss.ts.
 *
 *   npx tsx examples/sss.ts -s p256 -n 5 -t 3 -c 2,4,5
 */
import {
  shareSecret,
  combineSecretShares,
  combinePublicShares,
  isEqualSecret,
  isKeypair,
} from 'vsslib';
import type { Group, Point } from 'vsslib';
import { parseIndexes, parseOptions, runMain } from './cli';


/** Shares a fresh secret and reconstructs it, along with its public
 * counterpart, from the shares of the `qualified` shareholders */
export const runSss = async <P extends Point>(
  ctx: Group<P>, nrShares: number, threshold: number, qualified: number[]
) => {
  // Dealer: samples the secret and computes one share per shareholder
  const { secret, sharing } = await shareSecret(ctx, nrShares, threshold);
  const secretShares = await sharing.getSecretShares();
  const publicShares = await sharing.getPublicShares();

  // Combiner: interpolates the shares of a qualified set, i.e. at least t
  const isQualified = (share: { index: number }) => qualified.includes(share.index);
  const combinedSecret = await combineSecretShares(
    ctx, secretShares.filter(isQualified), threshold
  );
  const combinedPublic = await combinePublicShares(
    ctx, publicShares.filter(isQualified), threshold
  );
  return { secret, combinedSecret, combinedPublic };
}


runMain(module, async () => {
  const { ctx, nrShares, threshold, values } = parseOptions(`
usage: npx tsx examples/sss.ts [options]

Shares a secret and reconstructs it from a qualified set of shares.

  -c, --combine <INDEXES>     indexes of the qualified shares (default: 1..t)`, {
    combine: { type: 'string', short: 'c' },
  });
  const qualified = values.combine ?
    parseIndexes(values.combine as string) :
    Array.from({ length: threshold }, (_, i) => i + 1);

  const { secret, combinedSecret, combinedPublic } = await runSss(
    ctx, nrShares, threshold, qualified
  );
  console.log('secret reconstructed:', await isEqualSecret(ctx, combinedSecret, secret));
  console.log('public reconstructed:', await isKeypair(ctx, secret, combinedPublic));
});
