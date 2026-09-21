# Swift Fuzz

Swift Fuzz is a library to make it easy to integrate [libFuzzer](https://llvm.org/docs/LibFuzzer.html) into your Swift packages. It provides coverage-guided fuzzing for Swift packages. Add a nested `Fuzzing/` package,
write a closure, run `swift package fuzz`. No compiler flags anywhere.

```swift
import CBOR
import Fuzzing

let fuzzTargets: @Sendable () -> Void = {
    FuzzTarget("CBORDecode") { bytes in
        _ = try? CBOR.decode(bytes)
    }
}
```

The body receives a `Span<UInt8>`: bounds-checked, and non-escapable so the
compiler enforces that it does not outlive the call. Nothing in swift-fuzz's API
hands you a pointer, so a harness needs no `unsafe` even in a package with
`.strictMemorySafety()` enabled.

Which entry point you want depends on what the code under test takes:

| | body receives | use when |
|---|---|---|
| `FuzzTarget(_:_:)` | `Span<UInt8>` | the API takes a `Span` — nothing is copied |
| `FuzzTarget.bytes(_:_:)` | `[UInt8]` | the API takes a collection, which most do |
| `FuzzTarget.structured(_:_:)` | `FuzzedDataProvider` | you need several values out of one input |
| `FuzzTarget.async(_:_:)` | `[UInt8]`, `async` | the code under test is asynchronous |

`bytes` copies once per execution, which is invisible next to any real parsing
work. Reach for `Span` when the API can take one directly.

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

## Structured input

A fuzz body receives raw bytes, but most harnesses want a few typed values and
then a payload. `FuzzedDataProvider` does that decoding:

```swift
FuzzTarget.structured("Decode") { data in
    let depth = data.integer(in: 1...64)
    let strict = data.bool()
    _ = try? MyParser.parse(data.remainingBytes(), maximumDepth: depth, strict: strict)
}
```

Nothing here fails when the input is short: integers come back as zero, `bool()`
as `false`, byte requests are truncated. A fuzzer spends most of its time on
tiny inputs, so a provider that threw would turn the common case into an error
path and the harness into a pile of `guard`s.

**Bytes come from the front, control values from the back.** That is deliberate,
and copied from LLVM's `FuzzedDataProvider.h`: it keeps the payload contiguous
at a stable offset, so mutating it does not also shift every control value and
invalidate what the fuzzer has learned about them.

This is also the form to prefer under `.strictMemorySafety()` — the provider
owns the unsafe buffer, so the harness needs no `unsafe` of its own.

### Drawing several values

`chunk()` takes a length from the back of the input and that many bytes off the
front, which is the idiom for a harness that needs more than one value:

```swift
FuzzTarget.structured("URIParse") { data in
    let scheme = data.optionalText()   // nil when absent, "" is a different case
    let host = data.text()
    let path = data.remainingText()
    _ = URI(scheme: scheme, host: host, path: path)
}
```

`text()`, `optionalText()` and `remainingText()` are the UTF-8 forms, repairing
invalid sequences rather than failing.

A chunk's length is drawn against **what is left**, not against a fixed ceiling,
so each draw leaves something for the ones after it. That matters more than it
sounds: a length drawn from a fixed `0...255` exceeds what remains on almost any
realistic input, so the first draw takes everything and every later one comes
back empty. A harness pulling three header values out of a 46-byte input got 45
bytes, then nothing, then nothing — fuzzing one field and holding the other two
constant, with no sign anything was wrong. Drawing against the remaining input
hands the split back to the fuzzer, which is the point of keeping lengths at the
back where coverage feedback can learn them.

Use `remainingText()` or `remainingBytes()` for the last value a target draws,
when it genuinely should take the rest.

### Fuzzable

Types can build themselves from the provider:

```swift
struct Request: Fuzzable {
    var method: Method
    var path: String

    init(from provider: inout FuzzedDataProvider) {
        method = provider.caseOf() ?? .get
        path = provider.value()
    }
}

FuzzTarget.structured("Router") { data in
    _ = router.route(data.value(Request.self))
}
```

`init(from:)` cannot fail, for the same reason the provider cannot: a failable
initialiser would be taken by the majority of executions. Draw on the provider
in a fixed order and do not branch on how much is left, so that the same bytes
always produce the same value and a saved crashing input still reproduces.

Conformances ship for the integers, `Bool`, `Double`, `Float`, `String`,
`Optional` and `Array`. `Array` bounds its length at 256 — otherwise one byte of
input can ask for an enormous allocation, and the fuzzer spends its time on
out-of-memory reports instead of on your code.

## Asynchronous targets

libFuzzer's entry point is a synchronous C function that must run one input and
return, so there is nowhere to `await`. Use the asynchronous form and swift-fuzz
bridges the gap:

```swift
FuzzTarget.async("Routing") { bytes in
    _ = try? await app.testable().sendRequest(makeRequest(bytes))
}

FuzzTarget.structuredAsync("Routing") { data in
    var data = data
    let method = data.caseOf(HTTPMethod.self) ?? .GET
    _ = try? await app.handle(method, body: data.remainingBytes())
}
```

The body runs on a detached task while the fuzzing thread blocks until it
finishes. The provider is passed by value rather than `inout`, because an
`inout` argument cannot be held across a suspension point — rebind it as above.

**The body must not require the main actor.** libFuzzer runs the entry point on
the process's main thread, and this blocks it; `@MainActor` work is scheduled on
that same thread, so it would wait for a thread that is waiting for it. That
presents as a hang, not a crash. Server-side code (Vapor, NIO) is not
main-actor-isolated and is unaffected.

**It costs about 8×** on a trivial body — a task, a semaphore and a copy of the
input per execution. Measured on the example target over 15 seconds:

| | executions |
|---|---|
| synchronous | 5,954,712 |
| asynchronous | 733,614 |

That overhead is invisible against real asynchronous work and dominant against a
body that only parses a few bytes, so keep synchronous targets synchronous.

The bytes are copied, so unlike the synchronous forms the body may keep them.

## Several targets in one executable

libFuzzer allows exactly one `LLVMFuzzerTestOneInput` per binary, so swift-fuzz
dispatches between targets at startup instead. Declare as many as you like in
one `fuzzTargets` closure:

```swift
let fuzzTargets: @Sendable () -> Void = {
    FuzzTarget("Decode") { bytes in ... }
    FuzzTarget("RoundTrip") { bytes in ... }
}
```

```bash
swift package --allow-writing-to-package-directory fuzz --list
swift package --allow-writing-to-package-directory fuzz Decode --time 60
```

Each target keeps its own `Seeds/`, `Corpus/` and `Crashes/` directories, keyed
by name, so sharing an executable changes nothing about how findings are stored.
What it buys is one build instead of several; what it costs is a binary
instrumented for every target in it, so coverage counters include code the
target you are running never touches.

Names must be unique across the package. Running without a name lists what is
available rather than guessing.

The names live in a closure, so nothing outside the process can know them.
`swift package fuzz` builds the executable and asks it — the registry stays the
only place a target name is written down, and renaming one cannot leave a
manifest out of step.

## Usage

```
swift package --allow-writing-to-package-directory fuzz <target> [options]

  --time <seconds>     Stop after this many seconds.
  --jobs <n>           Run n fuzzing processes in parallel.
  --replay             Run the existing corpus once and exit. For CI.
  --coverage           Report which source files the corpus reaches.
  --uncovered          As --coverage, plus every function it never reached.
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

Nothing here requires `unsafe`. The fuzz body receives a `Span<UInt8>` and the
structured forms receive a `FuzzedDataProvider`; neither exposes a pointer, so a
harness in a package with `.strictMemorySafety()` enabled compiles clean:

```swift
let fuzzTargets: @Sendable () -> Void = {
    FuzzTarget("JSONParsing") { bytes in
        _ = try? JSONParser.parse(bytes)
    }
}
```

`Examples/` is built this way, with the setting on, so the pattern is compiled
and fuzzed on every CI run rather than merely described here.

If you need a pointer for an API that cannot take a `Span`, ask the span for one
at the point of need:

```swift
bytes.withUnsafeBufferPointer { buffer in
    legacyParse(buffer.baseAddress, buffer.count)
}
```

Note `Span` is not a `Sequence`, so there is no `Array(span)` or `reversed()`.
Copy by index when you genuinely need a collection.

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
reduces the inputs needed for the current build's observed features — and a
hand-written vector whose coverage is reachable some other way
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
byte-identical to a seed. Seeds are an input to the merge and are never written.
The merge uses the same runtime defaults as fuzzing, including value profiling;
pass the same feature overrides if you changed them during the original run.

Before replacing the corpus, swift-fuzz replays the original and candidate with
the same settings and refuses if the edge count decreases, or either
measurement fails. Value-profile totals can vary even when removing exact
copies of seeds, so selection of those features is left to libFuzzer's merge.
The edge count is a regression check, not proof of identical feature sets
across nondeterministic runs. Minimization is specific to the current build
and settings, and does not promise the mathematically smallest corpus.

An empty working corpus is valid when the seeds already retain the observed
coverage. Replacement keeps the original in a sibling backup until installation
succeeds and restores it on an installation error. If interruption or a second
filesystem error prevents recovery, the `.NAME.swift-fuzz-backup` directory
retains the original inputs; recover it before minimizing again.

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

## Coverage

Fuzzing has an uncomfortable failure mode: it runs happily for hours, reports no
crashes, and never got anywhere near the code you care about. `--coverage` runs
the corpus once and says where it actually went.

```bash
swift package --allow-writing-to-package-directory fuzz CBORDecode --coverage
```

```
swift-fuzz: coverage for CBORDecode
  2541 corpus inputs, 69 seeds

  FILE                    EDGES       FUNCTIONS
  CBORParser.swift      210/565    37%      21/21
  CBOR+Decode.swift      16/262     6%        1/6
  CBORTag.swift            8/66    12%       2/18
  CBOR+Identity.swift    89/139    64%        4/5
  CBOROptions.swift        4/36    11%        2/3
  CBORDecode.swift        12/35    34%        1/3
  CBORDecoder.swift      0/2589     0%       0/88
  CBOREncoder.swift      0/1703     0%       0/94
  CBOR+Encode.swift       0/547     0%       0/14
  CBOR+Accessors.swift    0/108     0%       0/11
  CBOR+Literals.swift      0/55     0%        0/7

  339/6105 edges reached (6%) across 11 files — 6 entered, 5 never entered
```

**Files the fuzzer entered come first**, ordered by how much of each is still
missing; files it never entered follow, largest first. That split is the one the
report turns on. A file at 37% is where a dictionary or better seeds pays off. A
file at 0% was never reached at all, and wants a target of its own — or belongs
to no target you have.

**Read the shape, not the headline.** 6% looks alarming and means little on its
own: the denominator is every file in the package, and this target only calls
the parser. `CBORParser.swift 21/21` is the line that matters — every function
in the parser is entered, so the target is wired up correctly and working the
code it was written for. The zeroes below are the encoder and the `Codable`
layer, which no decode target can reach.

Edges lead rather than functions because a function counts once however large it
is — a file of small accessors would otherwise outweigh the one parser that
matters.

swift-fuzz's own sources, `<compiler-generated>` thunks, and synthesized code
with no line to point at are all excluded, so what you are looking at is the code
you wrote.

### Packages with dependencies

libFuzzer instruments everything linked into the binary, which for a real
application is mostly other people's code. Fuzzing Vapor's URI parser
unscoped reports `44/628536 edges reached (0%) across 1455 files`, and the first
page is NIO, swift-collections and swift-configuration. Not one Vapor file
appears before the fold.

So the report covers **the package under test** by default: the fuzz package
itself, plus every package reached from it that is checked out locally rather
than fetched. A package you point at with a path is one you are working on; a
package from a repository or registry is one you are merely linking. The same
target then reads:

```
  FILE                          EDGES       FUNCTIONS
  URI.swift                    42/603     7%      12/37
  URITargets.swift               2/40     5%        1/4
  FileIO.swift                 0/2059     0%       0/57
  EndpointCache.swift          0/1547     0%       0/29
  ...

  44/44680 edges reached (0%) across 178 files — 2 entered, 176 never entered
  166 never-entered files not listed above
  1277 dependency files (583856 edges) excluded; --include-dependencies adds them
```

`URI.swift`, which is what `URIParse` exists to exercise, is now the first line
rather than the twenty-second. The never-entered tail is capped at ten so a
package with hundreds of files stays readable; what was left out is always
stated, never silently dropped. `--include-dependencies` widens the scope back
to everything linked in.

Matching is by file name, because that is all libFuzzer reports. Two packages
that both contain an `Extensions.swift` would let the dependency's copy through
— over-inclusion being much the safer direction.

### Naming what was missed

```bash
swift package --allow-writing-to-package-directory fuzz CBORDecode --uncovered
```

```
  Uncovered functions:
    CBORParser.swift
      CBORParser.parseBigNum()  CBORParser.swift:210
    ...
```

`--uncovered` also turns off the cap on never-entered files, so it is the full
picture rather than the readable summary.

### On macOS, add `--disable-sandbox`

```bash
swift package --disable-sandbox --allow-writing-to-package-directory \
  fuzz CBORDecode --coverage
```

libFuzzer turns addresses into function names by launching `llvm-symbolizer` as
a child process, and SwiftPM's macOS plugin sandbox denies that spawn — including
for a symbolizer inside the toolchain, so there is nothing swift-fuzz can
configure to avoid it. Without the flag you get a clear error rather than a
silently empty report. Linux has no plugin sandbox and needs nothing extra,
which is also why this is a non-issue in CI.

The same sandbox is why crash stack traces on macOS carry function names but no
file and line. `--disable-sandbox` restores those too.

swift-fuzz points the sanitizer runtime at the toolchain's `llvm-symbolizer`
itself, via `ASAN_SYMBOLIZER_PATH`. The runtime otherwise searches only `PATH`,
and a toolchain selected with `TOOLCHAINS` or `xcrun` frequently is not on it —
which produced a coverage run that built for forty minutes and then died with
`Failed to use and restart external symbolizer!`. If a symbolizer cannot be
found at all, `--coverage` now says so before starting the build rather than
after. Setting `ASAN_SYMBOLIZER_PATH` yourself still wins.


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
