#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
out=$(mktemp "${TMPDIR:-/tmp}/a2dp-progress.XXXXXX")
trap 'rm -f "$out"' EXIT HUP INT TERM
${CXX:-c++} -std=c++11 -Wall -Wextra -Werror -fsanitize=address,undefined \
    -Imain tests/br/a2dp_progress_test.cpp -o "$out"
"$out"
