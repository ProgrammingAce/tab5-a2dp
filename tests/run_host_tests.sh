#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
OUT=$(mktemp "${TMPDIR:-/tmp}/a2dp-br-tests.XXXXXX")
trap 'rm -f "$OUT"' EXIT HUP INT TERM
${CC:-cc} -std=c99 -O1 -Wall -Wextra -Werror \
  -Icomponents/br_baseband/include -Itests/br \
  components/br_baseband/src/*.c tests/br/*.c -o "$OUT"
"$OUT"
