// Compiled against the emitted declarations (npm run build), whose internal
// members are stripped, by npm run check:declarations: what a consumer of
// the package uses must still typecheck
import {
  initBackend,
  shareSecret,
  createFeldmanPackets,
  parseFeldmanPacket,
  derivePedersenBase,
  createPedersenPackets,
  parsePedersenPacket,
  createSchnorrPacket,
  recoverPublic,
  combineSecretShares,
  combinePublics,
} from '../../dist/index';
import type { ShamirSharing, SecretShare } from '../../dist/index';
import { Group, BadPointError, validateMultiExp } from '../../dist/backend/index';
import type { EcGroup, EcPoint } from '../../dist/backend/index';


export async function flows(): Promise<void> {
  const ctx: EcGroup = initBackend('ed25519');
  const { sharing } = await shareSecret(ctx, 5, 3);
  const typed: ShamirSharing<EcPoint> = sharing;
  const feldman = await createFeldmanPackets(typed);
  const shares: SecretShare[] = [];
  for (const packet of feldman.packets) {
    shares.push((await parseFeldmanPacket(ctx, feldman.commitments, packet, 3)).share);
  }
  const base = await derivePedersenBase(ctx);
  const pedersen = await createPedersenPackets(sharing, base);
  await parsePedersenPacket(ctx, pedersen.commitments, base, pedersen.packets[0], 3);
  const packets = await Promise.all(shares.map(share => createSchnorrPacket(ctx, share)));
  await recoverPublic(ctx, packets, 3);
  await combineSecretShares(ctx, shares.slice(0, 3), 3);
  await combinePublics(ctx, []);
}


/** A backend written with methods, as an external one would be */
export class External extends Group<EcPoint> {
  constructor(private inner: EcGroup) {
    super('external', inner.modulus, inner.order, inner.generator, inner.neutral);
  }
  async validatePoint(point: EcPoint): Promise<boolean> { return this.inner.validatePoint(point); }
  async exp(point: EcPoint, scalar: bigint): Promise<EcPoint> { return this.inner.exp(point, scalar); }
  async operate(lhs: EcPoint, rhs: EcPoint): Promise<EcPoint> { return this.inner.operate(lhs, rhs); }
  async invert(point: EcPoint): Promise<EcPoint> { return this.inner.invert(point); }
  bytesToPoint(bytes: Uint8Array): EcPoint {
    if (bytes.length === 0) throw new BadPointError('empty');
    return this.inner.bytesToPoint(bytes);
  }
  async hashToPoint(msg: Uint8Array, dst: Uint8Array): Promise<EcPoint> {
    return this.inner.hashToPoint(msg, dst);
  }
  async multiExpPublic(points: EcPoint[], scalars: bigint[]): Promise<EcPoint> {
    validateMultiExp(points, scalars, this.order);
    return this.inner.multiExpPublic(points, scalars);
  }
}
