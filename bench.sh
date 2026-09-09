#!/bin/bash

# Benchmarks of the high-level operations; see ./bench.sh --help

DIR="$(cd "$(dirname "$0")" && pwd)"

exec "$DIR/node_modules/.bin/tsx" --tsconfig "$DIR/tsconfig.json" "$DIR/bench/cli.ts" "$@"
