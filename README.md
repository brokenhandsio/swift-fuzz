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

## Corpus hygiene

The corpus is where the fuzzer's accumulated knowledge lives, and it is worth
committing: on swift-cbor the RFC 8949 seed vectors alone reach 340 coverage
edges, while the corpus after a few minutes of fuzzing reaches 507. A fresh
clone with the corpus starts there instead of rediscovering it, and `--replay`
in CI is only meaningful against a corpus with real coverage.

But libFuzzer keeps every input that adds a feature, so the raw directory grows
fast and most of it is redundant. Minimize before committing:

```bash
.build/<triple>/debug/<Target> -merge=1 Corpus.min Corpus/<Target> && mv Corpus.min Corpus/<Target>
```

On swift-cbor that took 5,109 files to 765 with **identical** edge coverage.
Verify with `-runs=0` over both directories and compare the `cov:` figure.

Commit `Corpus/`, `Crashes/` and `Dictionaries/`; ignore `.build/`. Crash
artefacts are regression tests — `--replay` re-runs them.
