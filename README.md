# swift-fuzz

Coverage-guided fuzzing for Swift packages. Add a nested `Fuzzing/` package,
write a closure, run `swift package fuzz`. No compiler flags anywhere.

```swift
import CBOR
import Fuzzing

let fuzzTargets: @Sendable () -> Void = {
    FuzzTarget("CBORDecode") { bytes in
        _ = try? CBOR.decode(Array(bytes))
    }
}
```

```bash
swift package --allow-writing-to-package-directory fuzz CBORDecode --time 60
```

## Requirements

A Swift toolchain that contains the libFuzzer runtime. It ships as a compiler-rt
archive inside the toolchain and is ABI-coupled to the instrumentation your
compiler emits, so it cannot be vendored or installed separately.

- **Linux** — the official `swift:6.3` Docker image or a swift.org tarball. Use
  the full image, not `-slim`, which has no compiler.
- **macOS** — the toolchain bundled with Xcode **does not** include it. Install
  one from swift.org (`swiftly install 6.3.3`) and select it with
  `export TOOLCHAINS=org.swift.<identifier>` or `xcrun --toolchain swift`.

`swift package fuzz` detects a toolchain without libFuzzer and says so, rather
than surfacing a raw linker error.

## Layout

```
YourRepo/
├── Package.swift                    ← library under test, untouched
└── Fuzzing/
    ├── Package.swift                ← root package when fuzzing
    ├── Seeds/<Target>/              ← optional; hand-written, never written to
    ├── Corpus/<Target>/             ← committed; see Corpus hygiene below
    ├── Crashes/<Target>/            ← crashing inputs land here
    ├── Dictionaries/<Target>.dict   ← optional, picked up automatically
    └── FuzzTargets/<Target>/…
```

Fuzzing lives in its own package so instrumented builds — unfit for any other
purpose — get their own `.build`, and your `swift build` and `swift test` stay
clean. It also matches the layout OSS-Fuzz expects.

## Two shapes

`FuzzTargetPlugin` generates different entry points depending on the kind of
target you attach it to. You choose the shape by how you write the manifest;
nothing else changes.

**Standalone** (Swift 6.4+) — one Swift executable target. The plugin generates
`LLVMFuzzerInitialize` and `LLVMFuzzerTestOneInput` directly into it.

```swift
.executableTarget(
    name: "JSONParsing",
    dependencies: [
        .product(name: "Fuzzing", package: "swift-fuzz"),
        .product(name: "MyLibrary", package: "MyRepo"),
    ],
    path: "FuzzTargets/JSONParsing",
    plugins: [.plugin(name: "FuzzTargetPlugin", package: "swift-fuzz")]
)
```

**Paired** (any supported toolchain) — a pure-C executable plus a Swift library.
The plugin, attached to the library, generates the two symbols `shim.c` calls.

```swift
.executableTarget(
    name: "JSONParsing",
    dependencies: ["JSONParsingTarget"],
    path: "FuzzTargets/JSONParsingShim"          // holds only shim.c
),
.target(
    name: "JSONParsingTarget",
    dependencies: [
        .product(name: "Fuzzing", package: "swift-fuzz"),
        .product(name: "MyLibrary", package: "MyRepo"),
    ],
    path: "FuzzTargets/JSONParsing",
    plugins: [.plugin(name: "FuzzTargetPlugin", package: "swift-fuzz")]
)
```

`shim.c` is six lines, identical for every target, and never edited — copy it
from `Examples/`.

`Examples/` has both shapes side by side, running the same harness against the
same library: `BuggyLibrary/Fuzzing` is paired, `StandaloneFuzzing` is
standalone. See `Examples/README.md`.

### Which to use

| Toolchain | Default backend | Paired | Standalone |
|---|---|---|---|
| 6.3.x | `native` | ✅ | ❌ |
| 6.4+ | `swiftbuild` | ✅ | ✅ |

Use **paired** if you support Swift 6.3.x. Use **standalone** once your floor is
6.4 — then `shim.c` and the second target both disappear. Attaching the plugin
to an executable target on 6.3.x is a build error explaining the constraint, not
a link failure.

Two independent things block standalone on 6.3.x:

- `native` cannot link a Swift fuzz executable at all. It renames the executable
  target's `main` to `<Module>_main` and aliases `main` to it, which collides
  with the `main` libFuzzer's runtime supplies: with `-parse-as-library` you get
  an undefined `<Module>_main`, without it a duplicate `main`. A C target has no
  Swift `main` to rename, so the collision never arises — this is the same
  approach grpc-swift uses.
- `swiftbuild` on 6.3.x forwards sanitizer flags to compilation but **not** to
  the link step, giving undefined `__sanitizer_cov_*` and `__asan_*` symbols.
  `otherLinkerFlags` are dropped there too, so a plugin cannot repair it.

So on 6.3.x the only working combination is `native` + paired, and it is the
default. swift-fuzz never passes `--build-system`.

## Usage

```
swift package --allow-writing-to-package-directory fuzz <target> [options]

  --time <seconds>     Stop after this many seconds.
  --jobs <n>           Run n fuzzing processes in parallel.
  --replay             Run the existing corpus once and exit. For CI.
  --reproduce <path>   Run one saved input, usually a crash artefact.
  --release            Build in release configuration.
  --sanitizers <list>  Default: fuzzer,address. --no-asan for fuzzer only.
```

Any other `-flag` goes straight to libFuzzer, so `-max_len=64`,
`-rss_limit_mb=4096`, `-dict=...` and `-minimize_crash=1` all work.

A crash exits non-zero and prints the artefact path plus a copy-pasteable
`--reproduce` command. `--replay` over a committed corpus is the CI regression
mode.

## Defaults, and why

| Default | Reason |
|---|---|
| `-sanitize=fuzzer,address` | ASan turns silent memory errors into findings. |
| `-use_value_profile=1` | libFuzzer ignores 1- and 2-byte comparisons otherwise. A 4-byte magic prefix survived 200k runs without it and fell in 16k with it. Byte-oriented format dispatch — CBOR major types, magic numbers — depends on this. |
| `-detect_leaks=0` | LeakSanitizer reports false positives on Swift runtime one-time allocations. |
| `SWIFT_BACKTRACE=enable=no` (Linux) | Swift's crash handler otherwise preempts libFuzzer's, so the crashing input is **never written** and the exit code is a bare signal. Findings would appear in the log and vanish from disk. |

Override any of them by passing the flag yourself; yours wins.

## Seeds and corpus

Two directories hold inputs, and the difference matters.

`Seeds/<Target>/` is yours: specification vectors, real-world samples, anything
you wrote or curated deliberately. swift-fuzz passes it to libFuzzer *after* the
corpus, which makes it read-only — discoveries are never written there.

`Corpus/<Target>/` is libFuzzer's: every input it has found that reached new
coverage. It grows on every run, including in CI.

The split exists because minimizing conflates the two otherwise. `-merge=1`
rewrites the directory it minimizes, keeping the smallest set that preserves
coverage — and a hand-written vector whose coverage is reachable some other way
is exactly what it deletes. swift-cbor lost all 69 of its RFC 8949 vectors that
way before this separation existed. Specification vectors are documentation as
much as coverage; a minimizer cannot know that.

### Minimizing

The corpus is worth committing: on swift-cbor the RFC seeds alone reach 340
coverage edges, seeds plus corpus reach 533. But most of the corpus is
redundant, so minimize before committing:

```bash
.build/<triple>/debug/<Target> -merge=1 Corpus.min Corpus/<Target> && mv Corpus.min Corpus/<Target>
```

That took swift-cbor's corpus from 1,703 files to 565 while combined coverage
moved 533 → 532. Minimizing the corpus alone leaves a little redundancy against
the seeds; merging both together would shave it, but at the cost of mixing the
two directories back up, which is the thing worth avoiding.

### What to commit, what to ignore

Commit `Seeds/`, `Corpus/`, `Crashes/` and `Dictionaries/`. Crash artefacts are
regression tests — `--replay` re-runs them.

It is tempting to gitignore `Corpus/` to stop runs dirtying the tree, but it
carries real value: on swift-cbor the seeds alone reach 341 coverage edges and
seeds plus corpus reach 533. Ignoring it would throw away 56% of the coverage
your replay gate exercises, and every clone would start from cold. The churn is
the price; minimize before committing.

A `Fuzzing/.gitignore` worth copying:

```gitignore
.build/

# libFuzzer's per-worker logs, written by --jobs.
/fuzz-*.log

# Artefacts libFuzzer drops in the working directory when the binary is run by
# hand without -artifact_prefix.
/crash-*
/leak-*
/timeout-*
/oom-*
```

**The leading slashes are load-bearing.** An unanchored `crash-*` matches at any
depth, so it would also hide new artefacts inside `Crashes/` — the single most
important thing to notice in `git status`. Check any pattern you add with a real
file, not a hypothetical path:

```bash
touch Crashes/SomeTarget/crash-test && git check-ignore -v Crashes/SomeTarget/crash-test
```

## Continuous integration

Fuzzing splits into two CI jobs with different jobs to do.

**Replay — on every push and pull request.** `--replay` runs the seeds, the
committed corpus and every saved crash artefact once each (`-runs=0`) and exits non-zero
if any of them still crashes. It is a regression test, not a search: it finishes
in seconds and never mutates anything, so it belongs on the critical path.

```yaml
- name: Replay corpus
  working-directory: Fuzzing
  run: swift package --allow-writing-to-package-directory fuzz MyTarget --replay
```

**Soak — on a schedule.** Actual fuzzing, time-boxed, looking for new bugs.
Nightly is a good default; it is the job that finds things.

```yaml
- name: Fuzz
  working-directory: Fuzzing
  run: swift package --allow-writing-to-package-directory fuzz MyTarget --time 600

- name: Upload crashing inputs
  if: failure()
  uses: actions/upload-artifact@v4
  with:
    name: crashes-MyTarget
    path: Fuzzing/Crashes/MyTarget/
```

Upload on `failure()` matters: the artefact is the only way to reproduce what
the runner found, and the container is gone once the job ends.

### Things that will bite you

**Crash artefacts are regression tests.** Anything in `Crashes/<Target>/` is
replayed on every run. Commit an artefact once the bug behind it is fixed and it
guards the fix forever. Commit one for a bug that is *not* yet fixed and CI is
red until it is — correct, but decide deliberately rather than by accident.

**Not every reproducer is deterministic.** A finding that depends on
`Dictionary` or `Set` iteration order will not reproduce reliably, because Swift
seeds their hashing per process. swift-cbor has one that fires about 40% of the
time from a single input. Check a candidate artefact by running it twenty times
before you rely on it as a gate; if it is intermittent, say so where you commit
it.

**The corpus grows on every run**, including in CI. A soak job's working corpus
is worth keeping — upload it as an artefact and merge it locally — but do not
commit it straight from CI without minimizing first. See Corpus hygiene above.

**Give the soak a `timeout-minutes`** comfortably above `--time`, and set
`fail-fast: false` on the matrix so one target crashing does not cancel the
others mid-search.

**A path dependency on swift-fuzz needs two checkouts.** `Fuzzing/Package.swift`
reaches this package with `.package(path: "../../swift-fuzz")`, which resolves
on your machine and not in a fresh CI checkout. Either check both repos out side
by side:

```yaml
- uses: actions/checkout@v7
  with: { path: your-repo }
- uses: actions/checkout@v7
  with: { repository: you/swift-fuzz, ref: main, path: swift-fuzz }
```

...or use a URL dependency, which is simpler once swift-fuzz is a released
version you can pin.

**Toolchains:** use a `container:` with a swift.org image such as `swift:6.3`.
GitHub's macOS runners ship Xcode's toolchain, which has no libFuzzer, so a
macOS fuzz job needs a swift.org toolchain installed and selected first.

## Working on swift-fuzz

```bash
swift test                                   # unit tests
cd Examples/BuggyLibrary/Fuzzing             # or Examples/StandaloneFuzzing on 6.4+
swift package --allow-writing-to-package-directory fuzz BuggyParse --time 60
```

CI runs the unit tests on Linux and macOS, fuzzes both examples for real on
Swift 6.3 and 6.4, and asserts that the standalone shape refuses cleanly on
6.3.x. The example jobs check three things a passing exit code would hide: that
the planted bug was actually found, that the crash propagated a non-zero status,
and that an artefact was written — without which `--reproduce` is impossible.

`Tests/FuzzCommandPluginTests/Arguments.swift` is a **symlink** to the command
plugin's copy. SwiftPM forbids a plugin target from depending on a library
target, so there is no module to import; compiling the real file a second time
is the only way to test it without a copy that drifts. Do not replace it with a
copy.
