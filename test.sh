#!/bin/bash

DEFAULT_MODULE="tests"
DEFAULT_RELOAD=false
DEFAULT_VERBOSE=false
DEFAULT_SYSTEM=""
DEFAULT_ELGAMAL_SCHEME=""
DEFAULT_SIGNATURE_SCHEME=""
DEFAULT_ALGORITHM=""
DEFAULT_AES_MODE=""
DEFAULT_NR_SHARES="3"
DEFAULT_NR_THRESHOLD="2"

usage_string="usage: ./$(basename "$0") [options]

TODO

Options
  -s, --system GROUP              TODO
  -es, --elgamal-scheme SCHEME    TODO
  -ss, --signature-scheme SCHEME  TODO
  -am, --aes-mode MODE            TODO
  -a, --algorithm HASH            TODO
  -n, --nr-shares NR              TODO
  -t, --threshold THRES           TODO
  -r, --reload                    Reload and run tests when saving changes
  -v, --verbose                   Be verbose
  -h, --help                      Display help message and exit

Examples:
  ./$(basename "$0") --system ed25519 --algorithm sha256
  ./$(basename "$0") backend --system ed25519
  ./$(basename "$0") nizk --system ed25519 --algorithms sha256
  ./$(basename "$0") keys --system ed25519 --algorithms sha256
  ./$(basename "$0") hash --algorithm sha256 --reload
"


set -e

usage() { echo -n "$usage_string" 1>&2; }

MODULE="$DEFAULT_MODULE"
RELOAD="$DEFAULT_RELOAD"
VERBOSE="$DEFAULT_VERBOSE"
SYSTEM="$DEFAULT_SYSTEM"
ELGAMAL_SCHEME="$DEFAULT_ELGAMAL_SCHEME"
SIGNATURE_SCHEME="$DEFAULT_SIGNATURE_SCHEME"
ALGORITHM="$DEFAULT_ALGORITHM"
AES_MODE="$DEFAULT_AES_MODE"
NR_SHARES="$DEFAULT_NR_SHARES"
THRESHOLD="$DEFAULT_THRESHOLD"

opts=()
while [[ $# -gt 0 ]]
do
    arg="$1"
    case $arg in
        -r|--reload)
            RELOAD=true
            shift
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -m|--module)
            MODULE="$2"
            shift
            shift
            ;;
        -am|--aes-mode)
            AES_MODE="$2"
            shift
            shift
            ;;
        -es|--elgamal-scheme)
            ELGAMAL_SCHEME="$2"
            shift
            shift
            ;;
        -ss|--signature-scheme)
            SIGNATURE_SCHEME="$2"
            shift
            shift
            ;;
        -a|--algorithm)
            ALGORITHM="$2"
            shift
            shift
            ;;
        -s|--system)
            SYSTEM="$2"
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

export AES_MODE="${AES_MODE}"
export ELGAMAL_SCHEME="${ELGAMAL_SCHEME}"
export SIGNATURE_SCHEME="${SIGNATURE_SCHEME}"
export ALGORITHM="${ALGORITHM}"
export SYSTEM="${SYSTEM}"
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

# NOTE: npm test -- --help
if [[ $TARGET == *"spec.ts" ]]; then
    npm test -- $opts --findRelatedTests "$TARGET"
else
    npm test -- $opts --findRelatedTests "$TARGET"/*
fi
