# Examples

Two runnable examples of the same fuzz target, packaged the two ways
`FuzzTargetPlugin` supports. The harness source (`BuggyParse.swift`) is
byte-identical in both — only the manifest differs.

`BuggyLibrary` is a tiny parser with a planted `fatalError`, reachable from a
four-byte input, so both examples find it within seconds and exit non-zero.

| | Shape | Toolchain | Run from |
|---|---|---|---|
| `BuggyLibrary/Fuzzing` | paired (C shim + Swift library) | any supported | `Examples/BuggyLibrary/Fuzzing` |
| `StandaloneFuzzing` | standalone (one Swift executable) | 6.4+ | `Examples/StandaloneFuzzing` |

```bash
cd BuggyLibrary/Fuzzing        # or: cd StandaloneFuzzing
swift package --allow-writing-to-package-directory fuzz BuggyParse --time 30
```

Expect a non-zero exit, a crashing input written to `Crashes/BuggyParse/`, and a
printed `--reproduce` command.

On Swift 6.3.x the standalone example deliberately fails to build, with an error
explaining why and pointing at the paired shape. That is the behaviour under
test — it is what stops the shape mismatch surfacing as an undefined-symbol link
failure.

The paired example uses the canonical `YourRepo/Fuzzing/` layout. The standalone
one sits beside the library instead of inside it only so that both shapes can
share a single library under test; in a real repo it would be `Fuzzing/` too.
