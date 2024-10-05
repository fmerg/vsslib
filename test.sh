#!/bin/bash

DEFAULT_MODULE="tests"
DEFAULT_RELOAD=false
DEFAULT_VERBOSE=false
DEFAULT_SYSTEM=""
DEFAULT_ALGORITHM=""
DEFAULT_NR_SHARES="3"
DEFAULT_NR_THRESHOLD="2"

usage_string="usage: ./$(basename "$0") [options]

Run tests with control over the orthogonal parameters below. For example, in
order to run dealer tests over ed25519 with hash algorithm SHA256 and reload, do

$ ./test.sh -m  --dealer sha256 --reload

Groups:
  ed25519, ed448, jubjub

Hash algorithms:
  sha224, sha256, SHA384, sha512, sha3-224, sha3-256, sha3-384, sha3-512

Options
  -m, --module <MODULE>             Tests to run. Can be any subfolder or file inside
                                    the ./tests folder. if not provided, all
                                    tests run.
  -s, --system <GROUP>              Underlying cryptosystem. If not provided, tests run
                                    against all supported groups.
  -a, --algorithm <HASH>            Hash algorithm to be used. This affects challenge
                                    computation for NIZK proofs (Fiat-Shamir transform).
                                    If not provided, related tests run against all
                                    supported hash algorithms.
  -n, --nr-shares <NR>              Number of shareholders for tests involving
                                    Shamir sharing (default: 3).
  -t, --threshold <THRESHOLD>       Threshold parameter for tests involving
                                    Shamir sharing (default: 2).
  -r, --reload                      Reload and run tests when saving changes.
  -v, --verbose                     Be verbose.
  -h, --help                        Display this help message and exit.

"

set -e

usage() { echo -n "$usage_string" 1>&2; }

MODULE="$DEFAULT_MODULE"
SYSTEM="$DEFAULT_SYSTEM"
ALGORITHM="$DEFAULT_ALGORITHM"
NR_SHARES="$DEFAULT_NR_SHARES"
THRESHOLD="$DEFAULT_THRESHOLD"
RELOAD="$DEFAULT_RELOAD"
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
            TRHESHOLD="$2"
            shift
            shift
            ;;
        -r|--reload)
            RELOAD=true
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
            opts+=($arg)
            shift
            ;;
    esac
done

export SYSTEM="${SYSTEM}"
export ALGORITHM="${ALGORITHM}"
export NR_SHARES="${NR_SHARES}"
export THRESHOLD="${THRESHOLD}"


TARGET=$MODULE
if [[ $TARGET != "tests"* ]]; then
    TARGET="tests/$TARGET"
fi


opts="--maxWorkers=1"
if [[ $RELOAD == "true" ]]; then
    opts+=" --watch"
fi
if [[ $VERBOSE == "true" ]]; then
    opts+=" --verbose"
fi

npm test -- --clearCache

# NOTE: npm test -- --help
if [[ $TARGET == *"spec.ts" ]]; then
    npm test -- $opts --findRelatedTests "$TARGET"
else
    npm test -- $opts --findRelatedTests "$TARGET"/*
fi
