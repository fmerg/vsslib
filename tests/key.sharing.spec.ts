import { key, backend } from '../src';
import { Messages } from '../src/key/enums';


describe('Key distribution', () => {
  test('Verifiable reconstruction - success', async () => {
    const { privateKey, publicKey } = await key.generate('ed25519');
    const n = 5;
    const t = 3;
    // const { privateShares, publicShares } = await privateKey.distribute(n, t);
    // console.log(privateShares.map((share: any) => share.serialize()));
    // console.log(publicShares.map((share: any) => share.serialize()));
  });
  test('Verifiable reconstruction - failure', async () => {
  });
});
