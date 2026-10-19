/** Verifiable Secret Sharing (VSS) followed by verifiable public recovery.
 *
 * Distribution: the dealer shares a secret and broadcasts commitments to the
 * sharing (Feldman, or Pedersen if a Pedersen base is given); every
 * shareholder verifies the packet sent to it in private against them.
 *
 * Public recovery: shareholders prove knowledge of their shares in Schnorr
 * packets, and the combiner verifies them and interpolates the public shares
 * into the public counterpart of the secret, without learning the secret.
 *
 *   npx tsx examples/vss.ts -s secp256k1 --pedersen -c 1,2,5
 */
import {
  shareSecret,
  derivePedersenBase,
  createFeldmanPackets,
  createPedersenPackets,
  parseFeldmanPacket,
  parsePedersenPacket,
  createSchnorrPacket,
  recoverPublic,
  randomNonce,
  isKeypair,
} from 'vsslib';
import type { Algorithm, Group, Nonces, Point, SecretShare } from 'vsslib';
import { parseIndexes, parseOptions, runMain } from './cli';


/** Shares a fresh secret verifiably; returns the secret and the shares as
 * extracted by the shareholders */
export const distributeShares = async <P extends Point>(
  ctx: Group<P>, nrShares: number, threshold: number, pedersenBase?: Uint8Array
) => {
  // Dealer: shares the secret and creates one packet per shareholder
  const { secret, sharing } = await shareSecret(ctx, nrShares, threshold);
  const { commitments, packets } = pedersenBase ?
    await createPedersenPackets(sharing, pedersenBase) :
    await createFeldmanPackets(sharing);

  // Shareholders: verify their packets against the broadcast commitments.
  // An invalid packet throws InvalidSecretShare, upon which the shareholder
  // would complain against the dealer; here the flow just aborts
  const shares: SecretShare[] = [];
  for (const packet of packets) {
    const { share } = pedersenBase ?
      await parsePedersenPacket(ctx, commitments, pedersenBase, packet, threshold) :
      await parseFeldmanPacket(ctx, commitments, packet, threshold);
    shares.push(share);
  }
  return { secret, shares };
}


/** Recovers the public counterpart of the shared secret from the given
 * shares, of which there must be at least t */
export const recoverPublicKey = async <P extends Point>(
  ctx: Group<P>, shares: SecretShare[], threshold: number, algorithm?: Algorithm
): Promise<Uint8Array> => {
  // Combiner: sends a fresh nonce to every shareholder, so that proofs
  // cannot be replayed from other sessions
  const nonces: Nonces = {};
  for (const { index } of shares) nonces[index] = randomNonce();

  // Shareholders: prove knowledge of their shares, bound to their nonces
  const packets = [];
  for (const share of shares) {
    const nonce = nonces[share.index];
    packets.push(await createSchnorrPacket(ctx, share, { algorithm, nonce }));
  }

  // Combiner: verifies all proofs and interpolates the public shares. A
  // failed proof throws InvalidPublicShare; pass errorOnInvalid: false to
  // get the indexes of all cheaters instead
  const { recovered } = await recoverPublic(ctx, packets, threshold, { algorithm, nonces });
  return recovered;
}


runMain(module, async () => {
  const { ctx, nrShares, threshold, values } = parseOptions(`
usage: npx tsx examples/vss.ts [options]

Distributes a secret verifiably and recovers its public counterpart from a
qualified set of shareholders.

  --pedersen                  use Pedersen instead of Feldman commitments
  -c, --combine <INDEXES>     indexes of the qualified shares (default: 1..t)`, {
    pedersen: { type: 'boolean' },
    combine: { type: 'string', short: 'c' },
  });
  const qualified = values.combine ?
    parseIndexes(values.combine as string) :
    Array.from({ length: threshold }, (_, i) => i + 1);

  // Public parameter of the Pedersen scheme, known to all parties
  const pedersenBase = values.pedersen ? await derivePedersenBase(ctx) : undefined;

  const { secret, shares } = await distributeShares(ctx, nrShares, threshold, pedersenBase);
  console.log(`shares verified: ${shares.length}`);
  const recovered = await recoverPublicKey(
    ctx, shares.filter(share => qualified.includes(share.index)), threshold
  );
  console.log('public recovered:', await isKeypair(ctx, secret, recovered));
});
