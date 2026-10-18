import { InvalidArgumentError, Option } from 'commander';
import { Systems } from 'vsslib';

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

export const systemOption = () => new Option('-s, --system <SYSTEM>', 'Underlying cryptosystem')
  .choices(Object.values(Systems))
  .default(Systems.ED25519);
