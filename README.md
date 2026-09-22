# Swift Fuzz

Coverage-guided fuzzing for Swift packages using [libFuzzer](https://llvm.org/docs/LibFuzzer.html).
Declare targets in a nested `Fuzzing` package; swift-fuzz handles instrumentation,
input storage, crash reproduction and coverage reporting.

## Requirements

- **Swift 6.3+**, with the libFuzzer runtime. Use an official Swift Docker image
  on Linux or a [swift.org toolchain](https://www.swift.org/install/) on macOS;
  Xcode's bundled toolchain does not include libFuzzer.
- **macOS 26+** when running on macOS. Declare that minimum in the fuzzing
  package; your library can keep its existing deployment target.
- Targets use a C shim on Swift 6.3. With Swift 6.4+, `fuzz-init --standalone`
  generates a single Swift executable instead. [Target layouts](Documentation/Usage.md#target-layouts)

## Setup

Create `Fuzzing/Package.swift` inside your repository:

```swift
// swift-tools-version: 6.3
import PackageDescription

let package = Package(
    name: "Fuzzing",
    platforms: [.macOS(.v26)],
    dependencies: [
        .package(path: "../"),
        .package(url: "https://github.com/brokenhandsio/swift-fuzz.git", from: "0.4.1"),
    ],
    targets: []
)
```

From `Fuzzing/`, scaffold a target:

```bash
swift package --allow-writing-to-package-directory fuzz-init JSONParsing
```

Paste the printed target declarations into the manifest and add your library
dependency. For the default paired layout:

```swift
    targets: [
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

Replace `YourLibrary` with your product name and `YourRepo` with the directory
name of the path dependency. The command creates sources and prints the stanza;
it does not edit the manifest.

Edit `FuzzTargets/JSONParsing/JSONParsing.swift` to exercise your API. For example,
this target parses arbitrary JSON with Foundation:

```swift
import Foundation
import Fuzzing

let fuzzTargets: @Sendable () -> Void = {
    FuzzTarget.bytes("JSONParsing") { bytes in
        _ = try? JSONSerialization.jsonObject(with: Data(bytes), options: .fragmentsAllowed)
    }
}
```

```bash
swift package --allow-writing-to-package-directory fuzz JSONParsing --time 60
```

Expected parse errors can be ignored; traps and sanitizer failures produce a
non-zero exit, a saved crash input, and a reproduction command.

## Targets

| Entry point | Input |
| --- | --- |
| `FuzzTarget(_:_:)` | Borrowed `Span<UInt8>`; no copy |
| `FuzzTarget.bytes(_:_:)` | Owned `[UInt8]` |
| `FuzzTarget.structured(_:_:)` | `inout FuzzedDataProvider` |
| `FuzzTarget.async(_:_:)` | Owned `[UInt8]`, async body |
| `FuzzTarget.structuredAsync(_:_:)` | `FuzzedDataProvider`, async body |

The owned forms copy the input once. Providers are `Sendable`; copies consume
their shared immutable input independently. All forms support strict memory safety.

```swift
FuzzTarget.structured("Decode") { data in
    let depth = data.integer(in: 1...64)
    let strict = data.bool()
    _ = try? MyParser.parse(data.remainingBytes(), maximumDepth: depth, strict: strict)
}
```

The provider reads payload bytes from the front and control values from the back.
It handles exhausted input without throwing. Use `text()` or `chunk()` for each
field, and `remainingText()` or `remainingBytes()` for the last payload.
[Structured input and custom types](Documentation/Usage.md#structured-input)

```swift
FuzzTarget.async("Routing") { bytes in
    _ = try? await app.testable().sendRequest(makeRequest(bytes))
}
```

Async bodies must not require the main actor: the fuzzing thread blocks until
they finish. Stalled bodies abort after 60 seconds; override with
`FUZZ_ASYNC_TIMEOUT`. Prefer synchronous targets for synchronous APIs.

Declare multiple targets in the same `fuzzTargets` closure and select them by
name. Names must be unique across the package, ignoring ASCII case, and match
`[A-Za-z_][A-Za-z0-9_-]{0,127}`. `llvm-symbolizer` and `llvm-symbolizer-swift` are
reserved. Names identify input directories and OSS-Fuzz executables.

**Upgrading from 0.4.x:** compact selection and `optionalText()` change how saved
inputs decode. Review important regression inputs before upgrading. The 1.x
decoding contract and migration instructions are in [Input compatibility](Sources/Fuzzing/Fuzzing.docc/InputCompatibility.md).

## Commands

Run commands from the fuzzing package:

```text
swift package --allow-writing-to-package-directory fuzz <target> [options]

  --list                   List logical targets (no target argument required).
  --time <seconds>          Limit fuzzing time.
  --jobs <n>                Run parallel fuzzing processes.
  --replay                  Replay seeds, working corpus and saved crashes.
  --reproduce <path>        Run one saved input.
  --minimize-corpus         Reduce the working corpus without changing seeds.
  --minimize-crash <path>   Shrink a crashing input in place.
  --coverage                Report source files reached by existing inputs.
  --uncovered               Also list unreached functions and all files.
  --include-dependencies    Include fetched dependencies in coverage reports.
  --release                 Build in release configuration.
  --sanitizers <list>        Override fuzzer,address; --no-asan uses fuzzer only.
```

Other `-flags` pass through to libFuzzer, including `-max_len`, `-rss_limit_mb`
and `-dict`. Defaults enable value profiling and disable leak checking. On Linux,
swift-fuzz disables Swift's backtrace handler so libFuzzer can save crash inputs.

## Seeds, corpus and crashes

| Path inside `Fuzzing/` | Purpose | Git policy |
| --- | --- | --- |
| `Seeds/<Target>/` | Curated inputs; never modified by fuzzing or minimization | Commit |
| `Corpus/<Target>/` | Accumulated discoveries | Can be entirely ignored |
| `Crashes/<Target>/` | Saved failing inputs; included in replay | Commit after fixing the bug |
| `Dictionaries/<Target>.dict` | Optional libFuzzer dictionary | Commit |

Missing working directories are created automatically. Starting from seeds alone
works, but discarding a corpus loses search progress; more runtime does not
guarantee recovering the same coverage. Preserve important discoveries as seeds
or regression tests and retain corpus snapshots separately when useful.

```gitignore
.build/
/Corpus/
/fuzz-*.log
/crash-*
/leak-*
/timeout-*
/oom-*
```

Keep the artifact patterns anchored so they do not hide files inside `Crashes/`.
For an already tracked corpus, `git rm -r --cached -- Corpus` removes it from
Git while keeping local files.

```bash
swift package --allow-writing-to-package-directory fuzz Decode --minimize-corpus
swift package --allow-writing-to-package-directory \
  fuzz Decode --minimize-crash Crashes/Decode/crash-abc123
```

Minimization is specific to the current build and feature settings. Crash
minimization preserves a crash, which may differ from the original failure;
keep important originals. [Minimization and recovery](Documentation/Usage.md#minimization-and-recovery)

## Coverage

```bash
swift package --allow-writing-to-package-directory fuzz Decode --coverage
```

Reports include the fuzzing package and local path dependencies by default.
Use `--include-dependencies` for fetched dependencies or `--uncovered` for all
unreached files and functions. swift-fuzz's own sources are excluded.

On macOS, add `--disable-sandbox` for symbolized coverage and crash locations:

```bash
swift package --disable-sandbox --allow-writing-to-package-directory \
  fuzz Decode --coverage
```

[Coverage details](Documentation/Usage.md#coverage)

## OSS-Fuzz

```bash
swift package --allow-writing-to-package-directory generate-oss-fuzz-script \
  --contact maintainer@example.com
```

Generates `OSSFuzz/` with a Dockerfile, build helpers, project metadata and a
validation script. The repository defaults to Git `origin`; use `--repository`
and `--output` to override the repository and destination.

- The builder pins Swift 6.3.3 independently of OSS-Fuzz's toolchain updates.
  For standalone targets, select a pinned Swift 6.4 Ubuntu 24.04 image with
  `--swift-image`.
- Each logical target becomes a native executable with its seeds, dictionary,
  options and SwiftPM resources. Corpus packaging requires `--include-corpus`.
- The default is x86_64 with address sanitizer. `--sanitizers address,thread`
  opts into thread sanitizer; validate every advertised configuration.
- Regeneration preserves `Dockerfile`, `project.yaml` and `build.sh`, and refuses
  to overwrite edits to generated helpers. Keep `.swift-fuzz-generated.json`.

Follow `OSSFuzz/README.md` to customize the integration and copy the submission
files into an OSS-Fuzz checkout. From that checkout, validate before submitting:

```bash
bash projects/PROJECT/validate.sh PROJECT
```

The script checks the advertised sanitizers and runs source coverage with the
packaged seeds. Existing integrations without generation state should use a new
`--output` directory and migrate their customizations.

## CI

Replay committed inputs on every pull request:

```yaml
- name: Replay fuzz inputs
  working-directory: Fuzzing
  run: swift package --allow-writing-to-package-directory fuzz Decode --replay
```

Run longer fuzzing jobs on a schedule, upload crash artifacts on failure, and
save/restore the working corpus between runs. [CI examples](Documentation/Usage.md#continuous-integration)

See [Examples](Examples/README.md) for runnable harnesses and
[Contributing](CONTRIBUTING.md) for development and validation commands.
