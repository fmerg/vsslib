import { ed25519 } from '@noble/curves/ed25519.js';
import { ed448 } from '@noble/curves/ed448.js';
import { jubjub } from '@noble/curves/misc.js';
import { System } from 'vsslib/types';


/** Encoding of the point (0, -1), which has order 2 on twisted Edwards curves */
const edwardsOrderTwo = (Point: typeof ed25519.Point) => Point.fromAffine(
  { x: 0n, y: Point.Fp.ORDER - 1n }
).toBytes();


export type SystemFixture = {
  scalarBytes: number,
  /** Default Pedersen base, pinned to catch changes of the derivation */
  defaultPedersenBase: string,
  /** Encoding of a point outside the prime-order subgroup; absent for prime-order groups */
  smallOrderPoint?: Uint8Array,
};


/** Per-system test data; a new system fails to compile until it has an entry */
export const fixtures: Record<System, SystemFixture> = {
  ed25519: {
    scalarBytes: 32,
    defaultPedersenBase: 'fed7bbcee7ed7e8101f3611762eb161ee9512f158699c1de88ccf6fc9711fabf',
    smallOrderPoint: edwardsOrderTwo(ed25519.Point),
  },
  ed448: {
    scalarBytes: 56,
    defaultPedersenBase: '9f20de8c2e08e3d1a7bfd2f871dbf122b05f521839c679559858d8966afd9453' +
      '1a4f8c63d2ca7ad0e59b4680bf55c65dba370bc40cc98e7880',
    smallOrderPoint: edwardsOrderTwo(ed448.Point),
  },
  jubjub: {
    scalarBytes: 32,
    defaultPedersenBase: '1140a506c84387ceebb0d0167f6b2ef192dbc149662908a8a4998e4dd667f24c',
    smallOrderPoint: edwardsOrderTwo(jubjub.Point),
  },
};
