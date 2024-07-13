import { InvalidArgumentError } from 'commander';

export const parseDecimal = (value) => {
  const parsedValue = parseInt(value, 10);
  if (isNaN(parsedValue)) {
    throw new InvalidArgumentError('Not a number.');
  }
  return parsedValue;
}

export const parseCommaSeparatedDecimals = (values) => {
  return values.split(',').map(v => parseDecimal(v))
}

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
