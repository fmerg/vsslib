#!/bin/bash

DEFAULT_MODULE="tests"
DEFAULT_WATCH=false
DEFAULT_BROWSERS=false
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

$ ./test.sh -m operations/recovery -s ed25519 -a sha256 --watch

Systems:
  ${SYSTEMS}

Hash algorithms:
  ${ALGORITHMS}

Options
  -m, --module <MODULE>             Tests to run. Can be any subfolder or spec file
                                    inside the ./tests folder, the latter with or
                                    without .spec.ts. If not provided, all tests
                                    run.
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
  -b, --browsers                    Run the flows of the browser bundle in Chromium,
                                    Firefox and WebKit (tests/browser/engines.ts)
                                    instead of the spec files; BROWSERS=chromium,firefox
                                    selects engines. Needs the browsers, see README.
                                    Writes the JUnit report to coverage/browsers.xml.
  -w, --watch                       Rerun tests when saving changes.
  -v, --verbose                     List every test, not only failures.
  -h, --help                        Display this help message and exit.

Other arguments are passed to node --test, e.g. --test-name-pattern <PATTERN>.
Any --test-reporter given replaces the default reporters, including the JUnit
report.

"

set -e

usage() { echo -n "$usage_string" 1>&2; }

MODULE="$DEFAULT_MODULE"
SYSTEM="$DEFAULT_SYSTEM"
ALGORITHM="$DEFAULT_ALGORITHM"
NR_SHARES="$DEFAULT_NR_SHARES"
THRESHOLD="$DEFAULT_THRESHOLD"
WATCH="$DEFAULT_WATCH"
RUN_BROWSERS="$DEFAULT_BROWSERS"
MODULE_GIVEN=false
VERBOSE="$DEFAULT_VERBOSE"

opts=()
while [[ $# -gt 0 ]]
do
    arg="$1"
    case $arg in
        -m|--module)
            MODULE="$2"
            MODULE_GIVEN=true
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
        -b|--browsers)
            RUN_BROWSERS=true
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
# Allow spec files without their suffix, e.g. operations/feldman; such a file
# takes precedence over a directory of the same name, e.g. tests/browser
if [[ -f $TARGET.spec.ts ]]; then
    TARGET="$TARGET.spec.ts"
fi
if [[ ! -e $TARGET ]]; then
    echo "No such test module: $MODULE" 1>&2
    exit 1
fi


# Spec files of the target, run by node's test runner with tsx compiling the
# sources; results also go to a JUnit report for CI
report=coverage/junit.xml
if [[ $RUN_BROWSERS == "true" ]]; then
    if [[ $MODULE_GIVEN == "true" ]]; then
        echo "Options --module and --browsers exclude each other" 1>&2
        exit 1
    fi
    files=(tests/browser/engines.ts)
    report=coverage/browsers.xml
    MODULE="browser/engines.ts"
elif [[ $TARGET == *"spec.ts" ]]; then
    files=("$TARGET")
else
    # No mapfile, which bash 3.2 (macOS) lacks
    files=()
    while IFS= read -r file; do
        files+=("$file")
    done < <(find "$TARGET" -name '*.spec.ts' | sort)
fi
if [[ ${#files[@]} -eq 0 ]]; then
    echo "No spec files in test module: $MODULE" 1>&2
    exit 1
fi

# Spec files run in parallel, each in its own process. The timeout fails a
# spec file that hangs instead of blocking the run; node applies it to each
# file as a whole, and the slowest take about 75 s locally. The browser run
# gets 30 minutes, above the timeouts of its three engines together (up to
# 9 minutes each, see tests/browser/engines.ts), so that these name a hang
timeout=600000
if [[ $RUN_BROWSERS == "true" ]]; then
    timeout=1800000
fi
# node warns of a listener leak on its own stream with three reporters or more
node_opts=(
    --import tsx --test --test-timeout="$timeout"
    --disable-warning=MaxListenersExceededWarning
)

# Reporters passed through replace the defaults, since node pairs every
# reporter with a destination
custom_reporter=false
nr_reporters=0
nr_destinations=0
for opt in "${opts[@]}"; do
    if [[ $opt == --test-reporter || $opt == --test-reporter=* ]]; then
        custom_reporter=true
        nr_reporters=$((nr_reporters + 1))
    elif [[ $opt == --test-reporter-destination* ]]; then
        nr_destinations=$((nr_destinations + 1))
    fi
done
if [[ $nr_destinations -gt 0 && $nr_destinations -ne $nr_reporters ]]; then
    echo "Give one --test-reporter-destination per --test-reporter, or none" 1>&2
    exit 1
fi
# Reporters given without destinations write to stdout, as node does for a
# single reporter, since the counting reporter below takes a destination
for ((i = nr_destinations; i < nr_reporters; i++)); do
    opts+=(--test-reporter-destination=stdout)
done
if [[ $custom_reporter == "false" ]]; then
    reporter=dot
    if [[ $VERBOSE == "true" ]]; then
        reporter=spec
    fi
    node_opts+=(
        --test-reporter="$reporter" --test-reporter-destination=stdout
        --test-reporter=junit --test-reporter-destination="$report"
    )
fi

# node passes when a name pattern or an empty case table selects no tests, so
# a reporter of ours counts the tests that ran, next to any other reporters.
# Not in watch mode, where the run never ends
count="${report%.xml}.count"
rm -f "$count"
if [[ $WATCH == "true" ]]; then
    node_opts+=(--watch)
else
    node_opts+=(
        --test-reporter=./tests/count-reporter.mjs
        --test-reporter-destination="$count"
    )
fi

mkdir -p coverage
status=0
node "${node_opts[@]}" "${opts[@]}" "${files[@]}" || status=$?

if [[ $status -eq 0 && $WATCH == "false" && $(cat "$count" 2>/dev/null) != [1-9]* ]]; then
    echo "No tests ran in test module: $MODULE" 1>&2
    exit 1
fi
exit $status
