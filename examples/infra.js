export const VssSchemes = Object.freeze({
  DEFAULT: 'feldman',
  FELDMAN: 'feldman',
  PEDERSEN: 'pedersen',
})

export class Party {
  constructor(ctx, index) {
    this.ctx = ctx;
    this.index = index;
    this.share = undefined;
  }
}

export class Combiner {
  constructor(ctx) {
    this.ctx = ctx;
    this.aggreagated = [];
  }
}

export const selectParty = (index, parties) => parties.filter(p => p.index == index)[0];
