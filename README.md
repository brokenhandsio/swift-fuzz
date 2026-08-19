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
    ├── Corpus/<Target>/             ← grows as the fuzzer finds new coverage
    ├── Crashes/<Target>/            ← crashing inputs land here
    ├── Dictionaries/<Target>.dict   ← optional, picked up automatically
    └── FuzzTargets/
        ├── <Target>/<Target>.swift  ← your closure
        └── <Target>Shim/shim.c      ← six lines, never edited
```

Fuzzing lives in its own package so instrumented builds — unfit for any other
purpose — get their own `.build`, and your `swift build` and `swift test` stay
clean. It also matches the layout OSS-Fuzz expects.

### Why each target is a pair

The executable is pure C and the harness is a Swift library. This is not
cosmetic. SwiftPM's `native` build system renames a *Swift* executable target's
`main` to `<Module>_main` and aliases `main` to it, which collides with the
`main` libFuzzer's runtime provides:

- with `-parse-as-library` → undefined `<Module>_main`
- without it → duplicate `main`

A C executable target has no Swift `main` to rename, so the collision never
arises and the same sources build under both `native` and `swiftbuild`. This is
the same approach grpc-swift uses. `shim.c` is identical for every target; copy
it from `Examples/`.

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

## Toolchain notes

Swift 6.3.x does not forward `-sanitize=fuzzer` to the link step under the
`swiftbuild` backend, so instrumentation lands but the runtime is never linked.
swift-fuzz detects that specific failure and links the archive itself. It does
this as a retry rather than unconditionally, because on 6.4 the driver already
links it, and doing it twice is a hard link error on Linux (`ld.gold: multiple
definition of 'fuzzer::...'`) even though Apple's linker silently tolerates it.
