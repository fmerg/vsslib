/** Threshold Schnorr signatures after D. R. Stinson and R. Strobl, "Provably
 * secure distributed Schnorr signatures and a (t, n) threshold scheme for
 * implicit certificates" (ACISP 2001), the elementary threshold variant of
 * Schnorr signatures: a coalition Q of at least t among n shareholders of a
 * key proves knowledge of the key with a common challenge, the message baked
 * into its hash, and the verifier aggregates the proofs into an ordinary
 * Schnorr signature.
 *
 * 0. Key generation: the n parties run a DKG for the key x, with public key
 *    y = g^x; party i holds the share x_i.
 * 1. Commitment: the members of Q run a DKG among themselves for the combined
 *    commitment u = g^r, r = Σ λ_i r_i over Q; member i keeps its share r_i
 *    private and learns u.
 * 2. Proofs: every member i computes u_i = g^(r_i) and s_i = r_i + c * x_i
 *    for the common challenge c = H(u, m), and sends (u_i, s_i) to the
 *    verifier.
 * 3. Verification: the verifier, also the combiner, interpolates
 *    s = Σ λ_i s_i and u = Π u_i^(λ_i), recomputes c = H(u, m) and accepts
 *    only if g^s = y^c * u. It needs only the public key y, not the public
 *    shares of the members.
 *
 * Every party runs in turn in one process; messages are function arguments.
 *
 *   npx tsx examples/tss.ts -s secp256k1 -n 5 -t 3 -c 1,3,5 -m "hello"
 */
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex } from '@noble/hashes/utils.js';
import {
  derivePedersenBase,
  shareSecret,
  createFeldmanPackets,
  parseFeldmanPacket,
  addSecrets,
  extractPublic,
  multiplyPublics,
  combineSecretShares,
  combinePublicShares,
  isEqualPublic,
} from 'vsslib';
import type { Group, Point, SecretShare, PublicShare } from 'vsslib';
import { runDkg } from './dkg';
import { parseIndexes, parseOptions, runMain } from './cli';


/** State of a coalition member after the commitment DKG */
export type Commitment = {
  /** Index of the member, that of its key share */
  index: number,
  /** Share r_i of the discrete log of the combined commitment, kept private */
  secret: Uint8Array,
  /** Combined commitment u */
  combined: Uint8Array,
};

/** Proof (u_i, s_i) of a coalition member, sent to the verifier */
export type Proof = { index: number, u: Uint8Array, s: Uint8Array };

/** Schnorr signature (u, s) */
export type Signature = { u: Uint8Array, s: Uint8Array };


/** Challenge c = H(u, m) modulo the group order; u has the fixed length of the
 * group's points, so that the concatenation is unambiguous */
const computeChallenge = <P extends Point>(
  ctx: Group<P>, u: Uint8Array, message: Uint8Array
): bigint => {
  const digest = sha256(new Uint8Array([...u, ...message]));
  return BigInt('0x' + bytesToHex(digest)) % ctx.order;
}


/** 0. All n parties: generate the key by DKG; returns the share of every
 * party and the public key */
export const generateKey = async <P extends Point>(
  ctx: Group<P>, nrShares: number, threshold: number, pedersenBase: Uint8Array
): Promise<{ shares: SecretShare[], publicKey: Uint8Array }> => {
  const { localShares, jointPublics } = await runDkg(ctx, nrShares, threshold, pedersenBase);
  return { shares: localShares, publicKey: jointPublics[0] };
}


/** 1. Coalition members: compute a fresh combined commitment by a DKG among
 * themselves (joint Feldman), with shares at their own indexes. Every member
 * deals a random secret to the others; its first Feldman commitment is the
 * public counterpart of that secret, and u is their product. The commitment
 * must never be reused, since two signatures under one commitment reveal the
 * key */
export const generateCommitment = async <P extends Point>(
  ctx: Group<P>, coalition: number[], threshold: number
): Promise<Commitment[]> => {
  // Shares are evaluated up to the highest index, and only those of the
  // members are sent
  const nrShares = Math.max(...coalition);
  const received: { [index: number]: Uint8Array[] } = {};
  for (const index of coalition) received[index] = [];
  const dealt: Uint8Array[] = [];
  for (let dealer = 0; dealer < coalition.length; dealer++) {
    // Dealer: shares a random secret, broadcasts the commitments and sends
    // each member its packet privately
    const { sharing } = await shareSecret(ctx, nrShares, threshold);
    const { packets, commitments } = await createFeldmanPackets(sharing);
    dealt.push(commitments[0]);
    // Members: verify their packets against the commitments
    for (const packet of packets.filter(packet => coalition.includes(packet.index))) {
      const { share } = await parseFeldmanPacket(ctx, commitments, packet, threshold);
      received[share.index].push(share.value);
    }
  }
  // Members: sum the received shares into r_i and the dealt public
  // counterparts into u
  const combined = await multiplyPublics(ctx, dealt);
  const states: Commitment[] = [];
  for (const index of coalition) {
    states.push({ index, secret: await addSecrets(ctx, received[index]), combined });
  }
  return states;
}


/** 2. Coalition member: proves knowledge of its key share with the common
 * challenge c = H(u, m), i.e. u_i = g^(r_i) and s_i = r_i + c * x_i */
export const createProof = async <P extends Point>(
  ctx: Group<P>, keyShare: SecretShare, commitment: Commitment, message: Uint8Array
): Promise<Proof> => {
  const c = computeChallenge(ctx, commitment.combined, message);
  const r = await ctx.parseScalar(commitment.secret);
  const x = await ctx.parseScalar(keyShare.value);
  const s = ctx.scalarToBytes((r + c * x) % ctx.order);
  const u = await extractPublic(ctx, commitment.secret);
  return { index: keyShare.index, u, s };
}


/** Whether `(u, s)` is a Schnorr signature of `message` under `publicKey`,
 * i.e. g^s = y^c * u for c = H(u, m) */
export const verifySignature = async <P extends Point>(
  ctx: Group<P>, publicKey: Uint8Array, message: Uint8Array, { u, s }: Signature
): Promise<boolean> => {
  const c = computeChallenge(ctx, u, message);
  // All values are public, so that variable time is safe
  const lhs = await ctx.expPublic(ctx.generator, await ctx.parseScalar(s));
  const rhs = await ctx.operate(
    await ctx.expPublic(await ctx.parsePoint(publicKey), c), await ctx.parsePoint(u)
  );
  return isEqualPublic(ctx, lhs.toBytes(), rhs.toBytes());
}


/** 3. Verifier, also the combiner: aggregates the proofs of at least t
 * members into s = Σ λ_i s_i and u = Π u_i^(λ_i), by interpolation over the
 * coalition, and accepts the signature (u, s) only if it verifies under the
 * public key */
export const aggregateProofs = async <P extends Point>(
  ctx: Group<P>, publicKey: Uint8Array, proofs: Proof[], threshold: number,
  message: Uint8Array,
): Promise<{ signature: Signature, isValid: boolean }> => {
  const sShares: SecretShare[] = proofs.map(({ index, s }) => ({ index, value: s }));
  const uShares: PublicShare[] = proofs.map(({ index, u }) => ({ index, value: u }));
  const signature = {
    u: await combinePublicShares(ctx, uShares, threshold),
    s: await combineSecretShares(ctx, sShares, threshold),
  };
  return { signature, isValid: await verifySignature(ctx, publicKey, message, signature) };
}


/** Signs `message` by the `coalition`, with the key shares of all parties
 * given by index - 1; runs steps 1 to 3 */
export const signMessage = async <P extends Point>(
  ctx: Group<P>, threshold: number, publicKey: Uint8Array, keyShares: SecretShare[],
  coalition: number[], message: Uint8Array,
) => {
  if (coalition.length < threshold) throw new Error(
    `Coalition smaller than the threshold: ${coalition.length} < ${threshold}`
  );
  for (const index of coalition) {
    if (!keyShares[index - 1]) throw new Error(`No key share at index ${index}`);
  }
  const commitments = await generateCommitment(ctx, coalition, threshold);
  const proofs: Proof[] = [];
  for (const commitment of commitments) {
    const keyShare = keyShares[commitment.index - 1];
    proofs.push(await createProof(ctx, keyShare, commitment, message));
  }
  return aggregateProofs(ctx, publicKey, proofs, threshold, message);
}


runMain(module, async () => {
  const { ctx, nrShares, threshold, values } = parseOptions(`
usage: npx tsx examples/tss.ts [options]

Threshold Schnorr signatures after Stinson and Strobl (ACISP 2001): a
coalition of at least t among n shareholders of a key computes a combined
commitment by DKG among its members and proves knowledge of the key with a
common challenge; the verifier aggregates the proofs into an ordinary Schnorr
signature.

  -c, --combine <INDEXES>     indexes of the coalition (default: 1..t)
  -m, --message <MESSAGE>     message to sign (default: "vsslib")`, {
    combine: { type: 'string', short: 'c' },
    message: { type: 'string', short: 'm', default: 'vsslib' },
  });
  const coalition = values.combine ?
    parseIndexes(values.combine as string) :
    Array.from({ length: threshold }, (_, i) => i + 1);
  const message = new TextEncoder().encode(values.message as string);

  // Public parameter of the Pedersen scheme of the key DKG
  const pedersenBase = await derivePedersenBase(ctx);

  const { shares, publicKey } = await generateKey(ctx, nrShares, threshold, pedersenBase);
  const { isValid } = await signMessage(ctx, threshold, publicKey, shares, coalition, message);
  console.log('signature verifies:', isValid);
});
