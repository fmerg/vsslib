/** Distributed Key Generation (DKG) after Pedersen: n parties jointly generate
 * a key, of which every party holds a share and nobody knows the secret.
 *
 * 1. Every party acts as the dealer of a Pedersen VSS of a fresh secret.
 * 2. Every party sums the shares it received into its local share, a share
 *    of the sum of all dealt secrets (the joint secret).
 * 3. Every party recovers the joint public key from the local shares of all
 *    parties, proven by Schnorr packets.
 *
 * All parties run in turn in one process; messages are function arguments.
 *
 *   npx tsx examples/dkg.ts -s ristretto255 -n 7 -t 4
 */
import {
  derivePedersenBase,
  addSecrets,
  addPublics,
  extractPublic,
  isEqualPublic,
} from 'vsslib';
import type { Algorithm, Group, Point, SecretShare } from 'vsslib';
import { distributeShares, recoverPublicKey } from './vss';
import { parseOptions, runMain } from './cli';


export const runDkg = async <P extends Point>(
  ctx: Group<P>, nrShares: number, threshold: number,
  pedersenBase: Uint8Array, algorithm?: Algorithm,
) => {
  // 1. Every party deals; received[i] holds the shares sent to party i + 1
  const secrets: Uint8Array[] = [];
  const received: Uint8Array[][] = Array.from({ length: nrShares }, () => []);
  for (let dealer = 1; dealer <= nrShares; dealer++) {
    const { secret, shares } = await distributeShares(ctx, nrShares, threshold, pedersenBase);
    secrets.push(secret);
    for (const share of shares) received[share.index - 1].push(share.value);
  }

  // 2. Every party sums the shares it received
  const localShares: SecretShare[] = [];
  for (let index = 1; index <= nrShares; index++) {
    localShares.push({ value: await addSecrets(ctx, received[index - 1]), index });
  }

  // 3. Every party recovers the joint public key, verifying the proofs of
  // all other parties under nonces of its own
  const jointPublics: Uint8Array[] = [];
  for (let party = 1; party <= nrShares; party++) {
    jointPublics.push(await recoverPublicKey(ctx, localShares, threshold, algorithm));
  }

  // Only `secrets` would stay private to their dealers in a real deployment;
  // it is returned for checking
  return { secrets, localShares, jointPublics };
}


runMain(module, async () => {
  const { ctx, nrShares, threshold } = parseOptions(`
usage: npx tsx examples/dkg.ts [options]

Runs a DKG among n parties and checks that all of them agree on the joint
public key.`, {});

  // Public parameter of the Pedersen scheme, known to all parties
  const pedersenBase = await derivePedersenBase(ctx);

  const { secrets, jointPublics } = await runDkg(ctx, nrShares, threshold, pedersenBase);

  // The joint public key is the sum of the public counterparts of all dealt
  // secrets, which nobody learns
  const expected = await addPublics(
    ctx, await Promise.all(secrets.map(secret => extractPublic(ctx, secret)))
  );
  for (const [i, jointPublic] of jointPublics.entries()) {
    console.log(`party ${i + 1} agrees:`, await isEqualPublic(ctx, jointPublic, expected));
  }
});
