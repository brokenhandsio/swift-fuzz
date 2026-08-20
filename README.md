# Swift Fuzz

Swift Fuzz is a library to make it easy to integrate [libFuzzer](https://llvm.org/docs/LibFuzzer.html) into your Swift packages. It provides coverage-guided fuzzing for Swift packages. Add a nested `Fuzzing/` package,
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

## Getting started

Fuzzing lives in a nested package so your library's own `Package.swift` is never
touched. Create `Fuzzing/` beside it:

```
YourRepo/
├── Package.swift        ← your library, unchanged
└── Fuzzing/
    └── Package.swift    ← the file below
```

Start with the dependencies and **no targets** — `fuzz-init` writes the target
sources, and SwiftPM refuses to load a manifest that names directories which do
not exist yet:

```swift
// swift-tools-version: 6.3
import PackageDescription

let package = Package(
    name: "Fuzzing",
    dependencies: [
        // Your library, and swift-fuzz. Note the `package:` label for a path
        // dependency is the *directory* name, not the name in its manifest.
        .package(path: "../"),
        .package(url: "https://github.com/brokenhandsio/swift-fuzz.git", from: "0.1.0"),
    ],
    targets: []
)
```

Then, from inside `Fuzzing/`:

```bash
swift package --allow-writing-to-package-directory fuzz-init JSONParsing
```

That writes the harness stub, the C shim and a `Seeds/` directory, and prints a
manifest stanza. Paste it into `targets:` and add your library to the Swift
target's dependencies:

```swift
    targets: [
        // A pure-C executable holding libFuzzer's entry points, and a Swift
        // library holding the harness. See "Two shapes" for why the executable
        // cannot be Swift.
        .executableTarget(
            name: "JSONParsing",
            dependencies: ["JSONParsingTarget"],
            path: "FuzzTargets/JSONParsingShim"
        ),
        .target(
            name: "JSONParsingTarget",
            dependencies: [
                .product(name: "Fuzzing", package: "swift-fuzz"),
                .product(name: "YourLibrary", package: "YourRepo"),
            ],
            path: "FuzzTargets/JSONParsing",
            plugins: [.plugin(name: "FuzzTargetPlugin", package: "swift-fuzz")]
        ),
    ]
```

Fill in the two TODOs in `FuzzTargets/JSONParsing/JSONParsing.swift`, then:

```bash
swift package --allow-writing-to-package-directory fuzz JSONParsing --time 60
```

`fuzz-init` cannot create the `Fuzzing` package itself — a plugin has to run
inside a package that already depends on swift-fuzz, and the whole point of the
nested layout is that your main package does not. That first manifest is the one
thing you paste by hand.

## Requirements

A Swift toolchain that contains the libFuzzer runtime. It ships as a compiler-rt
archive inside the toolchain and is ABI-coupled to the instrumentation your
compiler emits, so it cannot be vendored or installed separately.

- **Linux** — the official `swift:6.3` Docker image or later, or a swift.org
  tarball. Use the full image, not `-slim`, which has no compiler.
- **macOS** — the toolchain bundled with Xcode **does not** include it. Install
  one from swift.org (`swiftly install 6.3.3`) and select it with
  `export TOOLCHAINS=org.swift.<identifier>` or `xcrun --toolchain swift`.

swift-fuzz requires **Swift 6.3 or later** — its manifest is
`swift-tools-version: 6.3`, needed for `.strictMemorySafety()`. Verified end to
end on 6.3.3 and 6.4. (The runtime works as far back as 6.0, so if you need an
older toolchain the only blocker is the manifest.) Only the standalone target
shape needs 6.4.

Before building anything, `swift package fuzz` compiles and links a five-line
probe to check the toolchain can actually produce a fuzz binary. If it cannot,
you get the guidance above instead of a raw driver or linker error, in a couple
of seconds rather than after a full instrumented build.

The probe links rather than just compiling, because the two platforms fail
differently: macOS rejects `-sanitize=fuzzer` up front, while Linux accepts it
and only fails when the archive cannot be found at link time. It also passes an
explicit `-sdk` on macOS — without one it fails with `library 'c++' not found`,
which would be a false negative on a perfectly good toolchain.

The result is cached under `.build`, keyed on the compiler's path *and* version,
so it is paid once per toolchain. Version matters as well as path: `swiftly`
swaps what `swift-latest.xctoolchain` points at, and an in-place upgrade keeps
its path.

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

`shim.c` is identical for every target and never edited. `swift package
fuzz-init` writes it for you — see below.

`Examples/` has both shapes side by side, running the same harness against the
same library: `BuggyLibrary/Fuzzing` is paired, `StandaloneFuzzing` is
standalone. See `Examples/README.md`.

### Which to use

| Toolchain | Default backend | Paired | Standalone |
|---|---|---|---|
| 6.3.x | `native` | ✅ | ❌ |
| 6.4+ | `swiftbuild` | ✅ | ✅ |

Use **paired** if you support Swift 6.3.x. Use **standalone** once your
floor is 6.4 — then `shim.c` and the second target both disappear. Attaching the plugin
to an executable target on 6.3.x is a build error explaining the constraint, not
a link failure.

Two independent things block standalone on 6.3.x:

- `native` cannot link a Swift fuzz executable at all. It renames the executable
  target's `main` to `<Module>_main` and aliases `main` to it, which collides
  with the `main` libFuzzer's runtime supplies: with `-parse-as-library` you get
  an undefined `<Module>_main`, without it a duplicate `main`. A C target has no
  Swift `main` to rename, so the collision never arises — this is the same
  approach grpc-swift uses.
- `swiftbuild` on 6.3.x and earlier forwards sanitizer flags to compilation but
  **not** to the link step, giving undefined `__sanitizer_cov_*` and `__asan_*` symbols.
  `otherLinkerFlags` are dropped there too, so a plugin cannot repair it.

So on 6.3.x the only working combination is `native` + paired, and it is the
default. swift-fuzz never passes `--build-system`.

## Adding a target

```bash
swift package --allow-writing-to-package-directory fuzz-init JSONParsing
```

Writes the harness stub, the C shim (paired shape) and a `Seeds/` directory,
then prints the `Package.swift` stanza to paste in. Pass `--standalone` for the
shim-free shape on Swift 6.4+.

It does not edit `Package.swift` itself: doing that safely would mean parsing
and rewriting arbitrary Swift, and getting it wrong would corrupt the manifest
of a package that already works. Printing the stanza is the honest trade.

Creating the `Fuzzing` package itself is a one-off — copy the manifest from
`Examples/BuggyLibrary/Fuzzing/Package.swift`. A plugin cannot do it, because
the whole point of the nested layout is that your main package never depends on
swift-fuzz, so there is nowhere for a plugin to run until the nested package
exists.

## Usage

```
swift package --allow-writing-to-package-directory fuzz <target> [options]

  --time <seconds>     Stop after this many seconds.
  --jobs <n>           Run n fuzzing processes in parallel.
  --replay             Run the existing corpus once and exit. For CI.
  --reproduce <path>   Run one saved input, usually a crash artefact.
  --minimize-crash <path>
                       Shrink a crashing input, in place, to the smallest input
                       that still crashes.
  --release            Build in release configuration.
  --sanitizers <list>  Default: fuzzer,address. --no-asan for fuzzer only.
```

Any other `-flag` goes straight to libFuzzer, so `-max_len=64`,
`-rss_limit_mb=4096`, `-dict=...` and `-minimize_crash=1` all work.

A crash exits non-zero and prints the artefact path plus a copy-pasteable
`--reproduce` command. `--replay` over a committed corpus is the CI regression
mode.

## Strict memory safety

A fuzz body receives an `UnsafeRawBufferPointer` — that is libFuzzer's contract,
not a choice. In a package with `.strictMemorySafety()` enabled, that means the
`FuzzTarget` call and any use of `bytes` need the `unsafe` keyword:

```swift
let fuzzTargets: @Sendable () -> Void = {
    unsafe FuzzTarget("JSONParsing") { bytes in
        try? JSONParser.parse(unsafe Array(bytes))
    }
}
```

The code swift-fuzz generates is already annotated, so it compiles cleanly
whether or not you enable the setting.

Shape your library to take a safe type — `[UInt8]`, `Span<UInt8>` — and convert
at the harness boundary, as above. The unsafe pointer then never reaches the
code under test, and one `unsafe` covers the whole harness. `Examples/` is built
this way, with the setting on, so the pattern is compiled and fuzzed on every CI
run rather than merely described here.

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

The corpus is worth committing: on swift-cbor the seeds alone reach 341 coverage
edges and seeds plus corpus reach 533. But libFuzzer keeps every input that adds
a feature, so most of the directory is redundant:

```bash
swift package --allow-writing-to-package-directory fuzz MyTarget --minimize-corpus
```

```
swift-fuzz: minimized Corpus/CBORDecode
  1793 files, 120862 bytes
  579 files, 31026 bytes
Seeds/CBORDecode was not modified.
```

68% fewer files, 74% fewer bytes, and edge coverage unchanged at 533.

The merge runs over the seeds *and* the corpus, then drops any result that is
byte-identical to a seed. So the corpus ends up holding only what the seeds do
not already cover — minimizing the corpus in isolation would keep entries whose
coverage a seed already provides. Seeds are an input to the merge and are never
written.

If the merge produces nothing, the corpus is left alone: an empty result means
the binary failed, not that every input was redundant.

### Minimizing a crash

A crashing input straight out of the fuzzer is usually mostly padding. Shrink it
before you try to read it:

```bash
swift package --allow-writing-to-package-directory \
  fuzz MyTarget --minimize-crash Crashes/MyTarget/crash-abc123
```

```
swift-fuzz: minimized Crashes/MyTarget/crash-abc123 in place
  1004 bytes -> 4 bytes
```

This is what makes a finding readable. The bug swift-cbor's round-trip target
found came out as a 92-byte input; minimized to 22 bytes it was obviously a map
with two NaN keys, which was the whole diagnosis.

It rewrites the file in place, because the smaller input supersedes the original
as a regression test and keeping both would replay the same bug twice on every
run. libFuzzer only keeps inputs that still crash, so the result is crashing by
construction — though it does not check the crash is the *same* one. If a
minimized artefact stops looking like the bug you were chasing, the original is
in version control.

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

## OSS-Fuzz

```bash
swift package --allow-writing-to-package-directory generate-oss-fuzz-script
```

Writes `OSSFuzz/` containing `build.sh`, `project.yaml`, a `Dockerfile` and a
README explaining how to test locally and submit. The repository OSS-Fuzz should
clone is taken from your git `origin` and converted to an https URL, since the
builder clones anonymously and most remotes are SSH. Pass `--repository` to
override that. The fuzz target list is read
from the package rather than typed in, so regenerating after adding a target
keeps the script correct — a stale `build.sh` only fails inside OSS-Fuzz's
builder, where the feedback loop is slow.

OSS-Fuzz builds with plain `swift build` and its own `$SWIFTFLAGS`; this plugin
is not involved there. That works because the executable target is C, so the
graph-wide `-parse-as-library` in `$SWIFTFLAGS` is harmless — the same property
that makes the paired shape build under either build system.

Two constraints worth knowing before you plan a submission:

- OSS-Fuzz's `base-builder-swift` image currently ships **Swift 6.2.3**
  (Ubuntu 24.04) or 6.1.3 (20.04), so a package requiring 6.3 will not build
  there until the image is updated.
- Only the `address` and `thread` sanitizers are supported for Swift. Declaring
  `undefined` fails the build.

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

Documentation is a DocC archive, behind an environment gate so consumers never
resolve the plugin:

```bash
SWIFT_FUZZ_DOCC=1 swift package generate-documentation --target Fuzzing
```

`Tests/FuzzCommandPluginTests/Arguments.swift` is a **symlink** to the command
plugin's copy. SwiftPM forbids a plugin target from depending on a library
target, so there is no module to import; compiling the real file a second time
is the only way to test it without a copy that drifts. Do not replace it with a
copy.
