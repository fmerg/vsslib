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
