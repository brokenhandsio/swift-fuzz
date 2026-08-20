import BuggyLibrary
import Fuzzing

// Several fuzz targets in one executable. libFuzzer allows only one
// `LLVMFuzzerTestOneInput` per binary, so swift-fuzz dispatches between them at
// startup: `swift package fuzz <name>` sets FUZZ_TARGET, and the generated
// entry point selects from the registry.
//
// Sharing an executable means one build instead of several, at the cost of a
// binary instrumented for all of them. Each target still gets its own
// Seeds/Corpus/Crashes directories, keyed by name.
let fuzzTargets: @Sendable () -> Void = {
    FuzzTarget("Forwards") { bytes in
        try? BuggyLibrary.parse(bytes)
    }

    FuzzTarget("Backwards") { bytes in
        // A deliberately different view of the same input, so the two targets
        // are not interchangeable.
        //
        // `Span` is not a `Sequence`, so there is no `Array(span)` or
        // `reversed()` — copy by index when you genuinely need a collection.
        var reversed: [UInt8] = []
        reversed.reserveCapacity(bytes.count)
        for index in stride(from: bytes.count - 1, through: 0, by: -1) {
            reversed.append(bytes[index])
        }
        try? BuggyLibrary.parse(reversed.span)
    }

    // libFuzzer's entry point is synchronous, so an async body runs on a task
    // while the fuzzing thread blocks. Mixed freely with synchronous targets in
    // the same executable.
    FuzzTarget.async("Asynchronous") { bytes in
        try? await BuggyLibrary.parseAsync(bytes)
    }
}
