#!/bin/bash

DEFAULT_MODULE=""
DEFAULT_RELOAD=""
DEFAULT_SYSTEM=""
DEFAULT_SCHEME=""
DEFAULT_ALGORITHM=""
DEFAULT_AES_MODE=""
DEFAULT_NR_SHARES="3"
DEFAULT_NR_THRESHOLD="2"

usage_string="usage: ./$(basename "$0") [options]

TODO

Options
  -s, --system GROUP      TODO
  -a, --scheme SCHEME     TODO
  -a, --algorithm HASH    TODO
  -n, --nr-shares NR      TODO
  -t, --threshold THRES   TODO
  -r, --reload            Reload and run tests when saving changes
  -h, --help              Display help message and exit

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
SYSTEM="$DEFAULT_SYSTEM"
SCHEME="$DEFAULT_SCHEME"
ALGORITHM="$DEFAULT_ALGORITHM"
AES_MODE="$DEFAULT_AES_MODE"
NR_SHARES="$DEFAULT_NR_SHARES"
THRESHOLD="$DEFAULT_THRESHOLD"

opts=()
while [[ $# -gt 0 ]]
do
    arg="$1"
    case $arg in
        hash|hmac|aes|elgamal|core|shamir|signer|plain|ies|kem|andDlog|eqDlog|ddh|dlog|fiatShamir|genericLinear|okamoto|nizk|crypto|lagrange|keys|backend|arith|bitwise|serializers|decryption)
            MODULE="$arg"
            shift
            ;;
        -r|--reload)
            RELOAD=":reload"
            shift
            ;;
        --aes-mode)
            AES_MODE="$2"
            shift

            ;;
        --scheme)
            SCHEME="$2"
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


TARGET="test";
if [ ! -z $MODULE ]; then
  TARGET="${TARGET}-${MODULE}"
fi
if [ ! -z $RELOAD ]; then
  TARGET="${TARGET}:reload"
fi


export AES_MODE="${AES_MODE}"
export SCHEME="${SCHEME}"
export ALGORITHM="${ALGORITHM}"
export SYSTEM="${SYSTEM}"
export NR_SHARES="${NR_SHARES}"
export THRESHOLD="${THRESHOLD}"

npm run "${TARGET}"
