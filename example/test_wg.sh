#! /usr/bin/env bash

set -e
set -o pipefail

main() {
    local argv; argv=("$0" "$@")
    local n; n=1
    while (( n < "${#argv[@]}" )); do
        echo >&2 "Arg ${n}: \"${argv[n]}\""
        (( n += 1 ))
    done
    echo >&2 "STDIN: --------------------"
    cat
}

main "$@"
