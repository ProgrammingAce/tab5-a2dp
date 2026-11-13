#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
out=$(mktemp "${TMPDIR:-/tmp}/a2dp-progress.XXXXXX")
trap 'rm -f "$out"' EXIT HUP INT TERM
for t in a2dp_progress_test a2dp_rate_test; do
    ${CXX:-c++} -std=c++11 -Wall -Wextra -Werror -fsanitize=address,undefined \
        -Imain "tests/br/$t.cpp" -o "$out"
    "$out"
done
