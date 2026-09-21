#!/usr/bin/env bash
# Run from an example fuzz package after its planted bug has produced an
# artifact. CI uses disposable checkouts for these intentionally failing cases.
set -euo pipefail

package_options=(--allow-writing-to-package-directory)
if [[ $(uname -s) == Darwin ]]; then package_options=(--disable-sandbox "${package_options[@]}"); fi
fuzz() {
    swift package "${package_options[@]}" fuzz "$@"
}
expect_failure() {
    local log=$1 pattern=$2
    shift 2
    if fuzz "$@" > "$log" 2>&1; then
        echo "Expected failure: $*" >&2
        return 1
    fi
    if ! grep -q "$pattern" "$log"; then
        cat "$log" >&2
        return 1
    fi
}

artifact=$(find Crashes/BuggyParse -type f -name 'crash-*' -print -quit)
test -n "$artifact"
expect_failure reproduce.log 'Fatal error: planted bug' BuggyParse --reproduce "$artifact"
expect_failure replay-crash.log 'Fatal error: planted bug' BuggyParse --replay

# Force a shrinkable input so this tests replacement even when the first
# discovered input already had the minimum size.
padded="$artifact.padded-$$"
cp "$artifact" "$padded"
printf 'padding padding padding' >> "$padded"
before=$(wc -c < "$padded")
fuzz BuggyParse --minimize-crash "$padded" -runs=1000 > minimize-crash.log 2>&1
after=$(wc -c < "$padded")
test "$after" -lt "$before"
expect_failure minimized-reproduce.log 'Fatal error: planted bug' BuggyParse --reproduce "$padded"
rm "$padded"

if [[ ${1:-Paired} == Paired ]]; then
    for target in Asynchronous StructuredAsynchronous; do
        # First exercise successful async execution, then the same failure
        # path as the synchronous target, with an actual suspension in both.
        fuzz "$target" --release --replay > "$target-clean.log" 2>&1
        mkdir -p "Corpus/$target"
        cp "$artifact" "Corpus/$target/runtime-crash"
        expect_failure "$target-crash.log" 'Fatal error: planted bug' "$target" --release --replay
        test -n "$(find "Crashes/$target" -type f -name 'crash-*' -print -quit)"
        rm "Corpus/$target/runtime-crash"
    done
    FUZZ_ASYNC_TIMEOUT=1 expect_failure async-timeout.log 'did not finish within 1s' AsyncTimeout --release --replay
    test -n "$(find Crashes/AsyncTimeout -type f -name 'crash-*' -print -quit)"
fi
