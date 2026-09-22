# Usage reference

[README](../README.md) · [Input compatibility](../Sources/Fuzzing/Fuzzing.docc/InputCompatibility.md)

## Target layouts

`fuzz-init` generates a paired target by default: a C executable shim and a Swift
library with `FuzzTargetPlugin`. This supports Swift 6.3 and later. The shim needs
no customization.

With Swift 6.4+, `fuzz-init NAME --standalone` generates a single Swift executable:

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

Swift 6.3's native build system conflicts with libFuzzer's `main` in Swift
executable targets, and its `swiftbuild` backend drops sanitizer link flags.
The C shim avoids both limitations. swift-fuzz uses SwiftPM's default backend.

### Multiple registrations

```swift
let fuzzTargets: @Sendable () -> Void = {
    FuzzTarget("Decode") { bytes in /* ... */ }
    FuzzTarget("RoundTrip") { bytes in /* ... */ }
}
```

```bash
swift package --allow-writing-to-package-directory fuzz --list
swift package --allow-writing-to-package-directory fuzz RoundTrip --time 60
```

Every executable is inspected during discovery, and names are validated across
the package. A logical name takes precedence over a product alias. A product
name can select its sole registration when no logical name matches.

Targets sharing a product share a binary and its instrumentation, but keep
separate input directories. OSS-Fuzz exports select a registration by executable
basename; an explicit `FUZZ_TARGET` takes precedence.

## Structured input

`FuzzedDataProvider` owns its bytes. Payload reads consume from the front;
control values consume from the back. On exhaustion, unrestricted integers
produce zero, booleans produce false, and byte requests truncate.

```swift
FuzzTarget.structured("URIParse") { data in
    let scheme = data.optionalText()
    let host = data.text()
    let path = data.remainingText()
    _ = URI(scheme: scheme, host: host, path: path)
}
```

`text()`, `optionalText()` and `remainingText()` repair invalid UTF-8.
`optionalText()` distinguishes absent, empty and nonempty strings. `element(of:)`
and `caseOf()` use compact indices; `integer(in:)` uses the integer type's full
width except for a single-value range.

### Custom types

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

Standard conformances cover integers, `Bool`, `Double`, `Float`, `String`,
`Optional` and `Array`; arrays have at most 255 elements. Keep field order,
collection ordering and custom decoding stable to preserve saved inputs.
The [byte rules and migration guide](../Sources/Fuzzing/Fuzzing.docc/InputCompatibility.md)
define the 1.x contract.

### Structured async targets

```swift
FuzzTarget.structuredAsync("Routing") { data in
    var data = data
    let method = data.caseOf(HTTPMethod.self) ?? .GET
    _ = try? await app.handle(method, body: data.remainingBytes())
}
```

Async providers are passed by value; rebind to `var` to consume them. The body
runs on a detached task while libFuzzer blocks the main thread, so it must not
hop to the main actor. `FUZZ_ASYNC_TIMEOUT` controls the stall timeout (60 seconds
by default). Task scheduling adds overhead to each input.

## Minimization and recovery

Corpus minimization merges seeds and corpus with the same effective feature
settings as fuzzing, then removes results identical to seeds. Pass any feature
overrides used during the original run. Seeds are never modified; an empty
result is valid when seeds already retain the observed coverage.

Before replacement, swift-fuzz compares replay edge counts and refuses if the
count decreases or either measurement fails. This check does not prove identical
feature sets; value-profile selection is left to libFuzzer's merge. Results are
specific to the build and settings, and are not guaranteed to be minimal.

Replacement retains the original in a sibling backup until installation
succeeds. If interrupted recovery leaves `.NAME.swift-fuzz-backup`, recover the
original from there before retrying. Backups are removed after successful
replacement, so copy important crash inputs before minimizing them. libFuzzer
does not verify that a minimized input triggers the same bug.

## Coverage

The report orders entered files by unreached edges, followed by the largest
unentered files. Assess coverage of the API being fuzzed; the total also includes
code that this target cannot reach.

The default scope includes the fuzzing package and local path dependencies.
`--include-dependencies` adds fetched dependencies. Matching uses filenames, so
identically named files in different packages can cause over-inclusion.

The summary lists at most ten unentered files and reports how many were omitted.
`--uncovered` removes that cap and lists unreached functions with source locations.
Compiler-generated entries, synthesized entries without source lines, and
swift-fuzz's own sources are excluded.

On macOS, SwiftPM's plugin sandbox prevents `llvm-symbolizer` from launching.
Pass `--disable-sandbox` for coverage and crash file/line information. swift-fuzz
locates the selected toolchain's symbolizer; `ASAN_SYMBOLIZER_PATH` overrides it.

## Continuous integration

Use `--replay` on pull requests. It runs seeds, available corpus and saved crash
inputs without mutation, and exits non-zero on a failure.

For scheduled fuzzing, use a job timeout longer than `--time` and set matrix
`fail-fast: false`. Preserve logs and inputs even when a target finds a bug:

```yaml
- name: Fuzz
  working-directory: Fuzzing
  run: swift package --allow-writing-to-package-directory fuzz Decode --time 600

- name: Upload crashing inputs
  if: failure()
  uses: actions/upload-artifact@v7
  with:
    name: crashes-Decode
    path: Fuzzing/Crashes/Decode/

- name: Preserve the working corpus
  if: always()
  uses: actions/upload-artifact@v7
  with:
    name: corpus-Decode
    path: Fuzzing/Corpus/Decode/
    if-no-files-found: ignore
```

Restore a previous corpus snapshot before the next scheduled run. Keep important
discoveries in durable storage beyond a disposable cache or expiring artifact,
and separate corpus snapshots by target and input format.

Commit crash inputs after their bugs are fixed, or turn them into seeds/unit-test
fixtures. Check nondeterministic findings repeatedly before using them as a CI
gate; collection iteration order can affect Swift reproductions.

Use a Swift Docker image on Linux. macOS fuzzing needs a swift.org toolchain;
Xcode's compiler is sufficient for unit tests but lacks libFuzzer. Path
dependencies outside the project require matching sibling checkouts; a released
URL dependency avoids that CI setup.
