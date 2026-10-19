#!/bin/bash

DEFAULT_MODULE="tests"
DEFAULT_WATCH=false
DEFAULT_VERBOSE=false
DEFAULT_SYSTEM=""
DEFAULT_ALGORITHM=""
DEFAULT_NR_SHARES="3"
DEFAULT_THRESHOLD="2"

# Distinct values of an enum in src/enums.ts, comma-separated
enum_values() {
    node -e '
      const src = require("fs").readFileSync(process.argv[1], "utf8");
      const body = src.match(new RegExp(`enum ${process.argv[2]} \\{([^}]*)\\}`))[1];
      const values = [...body.matchAll(/^\s*\w+\s*=\s*\x27([^\x27]+)\x27/gm)].map(m => m[1]);
      console.log([...new Set(values)].join(", "));
    ' "$(dirname "$0")/src/enums.ts" "$1"
}

SYSTEMS=$(enum_values Elliptic)
ALGORITHMS=$(enum_values Algorithms)
if [[ -z "$SYSTEMS" || -z "$ALGORITHMS" ]]; then
    echo "Could not read the supported systems and algorithms from src/enums.ts" 1>&2
    exit 1
fi

usage_string="usage: ./$(basename "$0") [options]

Run tests with control over the orthogonal parameters below. For example, in
order to run the public recovery tests over ed25519 with SHA256 and rerun them
on changes, do

$ ./test.sh -m operations/recovery.spec.ts -s ed25519 -a sha256 --watch

Systems:
  ${SYSTEMS}

Hash algorithms:
  ${ALGORITHMS}

Options
  -m, --module <MODULE>             Tests to run. Can be any subfolder or file inside
                                    the ./tests folder. if not provided, all
                                    tests run.
  -s, --system <SYSTEM>             Underlying cryptosystem. If not provided, tests run
                                    against all supported systems.
  -a, --algorithm <HASH>            Hash algorithm to be used. This affects challenge
                                    computation for NIZK proofs (Fiat-Shamir transform).
                                    If not provided, related tests run against all
                                    supported hash algorithms.
  -n, --nr-shares <NR>              Number of shareholders for tests involving
                                    Shamir sharing (default: 3).
  -t, --threshold <THRESHOLD>       Threshold parameter for tests involving
                                    Shamir sharing (default: 2).
  -w, --watch                       Rerun tests when saving changes.
  -v, --verbose                     Be verbose.
  -h, --help                        Display this help message and exit.

Other arguments are passed to Jest, e.g. --bail or --testNamePattern <PATTERN>.

"

set -e

usage() { echo -n "$usage_string" 1>&2; }

MODULE="$DEFAULT_MODULE"
SYSTEM="$DEFAULT_SYSTEM"
ALGORITHM="$DEFAULT_ALGORITHM"
NR_SHARES="$DEFAULT_NR_SHARES"
THRESHOLD="$DEFAULT_THRESHOLD"
WATCH="$DEFAULT_WATCH"
VERBOSE="$DEFAULT_VERBOSE"

opts=()
while [[ $# -gt 0 ]]
do
    arg="$1"
    case $arg in
        -m|--module)
            MODULE="$2"
            shift
            shift
            ;;
        -s|--system)
            SYSTEM="$2"
            shift
            shift
            ;;
        -a|--algorithm)
            ALGORITHM="$2"
            shift
            shift
            ;;
        -n|--nr-shares)
            NR_SHARES="$2"
            shift
            shift
            ;;
        -t|--threshold)
            THRESHOLD="$2"
            shift
            shift
            ;;
        -w|--watch)
            WATCH=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            opts+=("$arg")
            shift
            ;;
    esac
done

if [[ -n "$SYSTEM" && ", $SYSTEMS, " != *", $SYSTEM, "* ]]; then
    echo "Unsupported system: $SYSTEM (supported: $SYSTEMS)" 1>&2
    exit 1
fi
if [[ -n "$ALGORITHM" && ", $ALGORITHMS, " != *", $ALGORITHM, "* ]]; then
    echo "Unsupported algorithm: $ALGORITHM (supported: $ALGORITHMS)" 1>&2
    exit 1
fi

export SYSTEM="${SYSTEM}"
export ALGORITHM="${ALGORITHM}"
export NR_SHARES="${NR_SHARES}"
export THRESHOLD="${THRESHOLD}"


TARGET=$MODULE
if [[ $TARGET != "tests"* ]]; then
    TARGET="tests/$TARGET"
fi


jest_opts=()
if [[ $WATCH == "true" ]]; then
    jest_opts+=(--watch)
fi
if [[ $VERBOSE == "true" ]]; then
    jest_opts+=(--verbose)
fi
jest_opts+=("${opts[@]}")

npm test -- --clearCache

# NOTE: npm test -- --help
if [[ $TARGET == *"spec.ts" ]]; then
    npm test -- "${jest_opts[@]}" --findRelatedTests "$TARGET"
else
    npm test -- "${jest_opts[@]}" --findRelatedTests "$TARGET"/*
fi
