# Contributing

```bash
swift test
swift Scripts/check-readme.swift
```

With a toolchain that includes libFuzzer:

```bash
swift Scripts/check-readme.swift --run
cd Examples/BuggyLibrary/Fuzzing
swift package --allow-writing-to-package-directory fuzz BuggyParse --time 30
bash ../../../Scripts/check-runtime.sh Paired
```

The example intentionally crashes; expect a non-zero status and an artifact in
`Crashes/BuggyParse/`. [Examples](Examples/README.md) describes both target layouts.

Run OSS-Fuzz validation on a Linux Docker host:

```bash
bash Scripts/check-oss-fuzz.sh
```

This builds the generated integration and checks native exports, async execution,
resource relocation, seeds, crash capture and source coverage in the official
OSS-Fuzz runner. Logs are written to `.build/oss-fuzz-validation/`.

Build DocC documentation with the development-only dependency enabled:

```bash
SWIFT_FUZZ_DOCC=1 swift package generate-documentation --target Fuzzing --warnings-as-errors
```

Tests symlink plugin sources because SwiftPM plugins cannot be imported by test
targets. Keep those symlinks; copies would drift from the code being tested.
