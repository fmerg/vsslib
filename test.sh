#!/bin/bash

DEFAULT_MODULE=""
DEFAULT_RELOAD=""

usage_string="usage: ./$(basename "$0") [options]

Options
  --reload    Reload and run tests when saving changes
  -h, --help  Display help message and exit
"

set -e

usage() { echo -n "$usage_string" 1>&2; }

RELOAD="$DEFAULT_RELOAD"

opts=()
while [[ $# -gt 0 ]]
do
    arg="$1"
    case $arg in
        elgamal|key|tds|shamir)
            MODULE="-$arg"
            shift
            ;;
        --reload)
            RELOAD=":reload"
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

npm run test${MODULE}${RELOAD}
