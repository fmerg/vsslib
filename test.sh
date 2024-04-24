#!/bin/bash

DEFAULT_MODULE=""
DEFAULT_RELOAD=""
DEFAULT_SYSTEM=""
DEFAULT_ALGORITHM=""
DEFAULT_AES_MODE=""

usage_string="usage: ./$(basename "$0") [options]

TODO

Options
  --system GROUP      TODO
  --algorithm HASH    TODO
  --reload            Reload and run tests when saving changes
  -h, --help          Display help message and exit

Examples:
  ./$(basename "$0") --system ed25519 --algorithm sha256
  ./$(basename "$0") backend --system ed25519
  ./$(basename "$0") sigma --system ed25519 --algorithms sha256
  ./$(basename "$0") key --system ed25519 --algorithms sha256
  ./$(basename "$0") hash --algorithm sha256 --reload
"

set -e

usage() { echo -n "$usage_string" 1>&2; }

MODULE="$DEFAULT_MODULE"
RELOAD="$DEFAULT_RELOAD"
SYSTEM="$DEFAULT_SYSTEM"
AES_MODE="$DEFAULT_AES_MODE"
ALGORITHM="$DEFAULT_ALGORITHM"

opts=()
while [[ $# -gt 0 ]]
do
    arg="$1"
    case $arg in
        hash|hmac|aes|elgamal|key|tds|shamir|signer|plain|ies|kem|andDlog|eqDlog|ddh|dlog|fiatShamir|linearDlog|okamoto|sigma|core|lagrange|key|backend|arith|bitwise)
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
        -a|--algorithm)
            ALGORITHM="$2"
            shift
            ;;
        -s|system)
            SYSTEM="$2"
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
export ALGORITHM="${ALGORITHM}"
export SYSTEM="${SYSTEM}"

npm run "${TARGET}"
