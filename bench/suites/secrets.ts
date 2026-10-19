import {
  randomSecret,
  randomPublic,
  extractPublic,
  derivePedersenBase,
  addSecrets,
  addPublics,
} from 'vsslib';
import { Ctx, Suite, defineCase } from '../types';


const randomSecrets = async (ctx: Ctx, count: number) => {
  const secrets = [];
  for (let i = 0; i < count; i++) secrets.push(await randomSecret(ctx));
  return secrets;
}


const suite: Suite = {
  module: 'secrets',
  cases: [
    defineCase({
      name: 'randomSecret',
      uses: [],
      setup: async () => undefined,
      run: async (ctx) => randomSecret(ctx),
    }),
    defineCase({
      name: 'randomPublic',
      uses: [],
      setup: async () => undefined,
      run: async (ctx) => randomPublic(ctx),
    }),
    defineCase({
      name: 'extractPublic',
      uses: [],
      setup: async (ctx) => (await randomSecret(ctx)).secret,
      run: async (ctx, secret) => extractPublic(ctx, secret),
    }),
    defineCase({
      name: 'derivePedersenBase',
      uses: [],
      setup: async () => undefined,
      run: async (ctx) => derivePedersenBase(ctx),
    }),
    // One summand per party, as in DKG
    defineCase({
      name: 'addSecrets',
      uses: ['nrShares'],
      setup: async (ctx, { nrShares }) => (
        await randomSecrets(ctx, nrShares)).map(s => s.secret
      ),
      run: async (ctx, secrets) => addSecrets(ctx, secrets),
    }),
    defineCase({
      name: 'addPublics',
      uses: ['nrShares'],
      setup: async (ctx, { nrShares }) => (
        await randomSecrets(ctx, nrShares)).map(s => s.publicBytes
      ),
      run: async (ctx, publics) => addPublics(ctx, publics),
    }),
  ],
};

export default suite;
