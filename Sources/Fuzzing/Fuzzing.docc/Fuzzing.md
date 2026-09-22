# ``Fuzzing``

Coverage-guided fuzzing for Swift packages, without writing a compiler flag.

## Overview

A fuzz target is a name and a closure. Declare targets inside a `fuzzTargets`
closure, and `swift package fuzz` builds the code under test with
instrumentation, runs libFuzzer against it, and saves anything that crashes.

```swift
import CBOR
import Fuzzing

let fuzzTargets: @Sendable () -> Void = {
    FuzzTarget("CBORDecode") { bytes in
        _ = try? CBOR.decode(bytes)
    }
}
```

```bash
swift package --allow-writing-to-package-directory fuzz CBORDecode --time 60
```

The closure runs millions of times on arbitrary, mostly-malformed input.
Swallow the failures you expect — `try?` a throwing parser — and let everything
else through: a trap, a failed precondition, an integer overflow or unbounded
recursion are all reported as crashes, which is the point.

Input arrives as a `Span<UInt8>`. It is bounds-checked, and non-escapable so the
compiler enforces that it does not outlive the call. No API here hands out a
pointer, so a harness compiles clean in a package with `.strictMemorySafety()`
enabled. Copy anything you need to keep; if you need a pointer for an API that
cannot take a `Span`, ask for one with `withUnsafeBufferPointer(_:)`.

### Beyond raw bytes

Most harnesses want a few typed values and then a payload rather than a byte
buffer. ``FuzzedDataProvider`` decodes one input into whatever the code under
test takes, and ``Fuzzable`` lets a type build itself from one:

```swift
FuzzTarget.structured("Decode") { data in
    let depth = data.integer(in: 1...64)
    _ = try? MyParser.parse(data.remainingBytes(), maximumDepth: depth)
}
```

Nothing there fails when the input runs short — integers read as zero, byte
requests truncate — because a fuzzer spends most of its time on tiny inputs, and
a harness that returns early on short input stops exercising the code it was
written for.

The provider owns its input and may outlive the body. Copies preserve the
current consumption position, then advance independently. Structured targets
copy libFuzzer's input once per execution; the `Span` entry point remains the
zero-copy option.

### Asynchronous code

libFuzzer's entry point is a synchronous C function, so there is nowhere to
`await`. ``FuzzTarget/async(_:_:)`` runs the body on a task and blocks until it
finishes, which makes server-side code fuzzable:

```swift
FuzzTarget.async("Routing") { bytes in
    _ = try? await app.testable().sendRequest(makeRequest(bytes))
}
```

The body must not require the main actor — libFuzzer owns that thread and this
blocks it. Being `@Sendable` already stops the closure inheriting main-actor
isolation; an explicit hop inside the body is reported as a stall rather than
hanging.

## Topics

### Declaring a fuzz target

- ``FuzzTarget``

### Reading typed values

- ``FuzzedDataProvider``
- ``Fuzzable``
