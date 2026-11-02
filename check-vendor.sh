#!/usr/bin/env bash
# Checks that bin/scout is the file scout.lock names. With --upstream it also
# downloads bin/scout from Luddite Scout at that commit and compares the bytes.
set -euo pipefail
root=$(cd "$(dirname "$0")" && pwd)
commit=$(sed -n 's/^commit=\([0-9a-f]\{40\}\)$/\1/p' "$root/scout.lock")
want=$(sed -n 's/^sha256=\([0-9a-f]\{64\}\)$/\1/p' "$root/scout.lock")
[ -n "$commit" ] && [ -n "$want" ] || { echo "scout.lock is malformed" >&2; exit 1; }
have=$(sha256sum "$root/bin/scout" | cut -d' ' -f1)
[ "$have" = "$want" ] || { echo "bin/scout does not match scout.lock ($have)" >&2; exit 1; }
if [ "${1:-}" = "--upstream" ]; then
  up=$(curl -fsSL --proto '=https' "https://raw.githubusercontent.com/TechLuddite/Luddite-Scout/$commit/bin/scout" | sha256sum | cut -d' ' -f1)
  [ "$up" = "$want" ] || { echo "bin/scout at $commit upstream is $up, not $want" >&2; exit 1; }
fi
echo "bin/scout matches scout.lock (commit $commit)"
