import BuggyLibrary
import Fuzzing

// Two fuzz targets in one executable. libFuzzer allows only one
// `LLVMFuzzerTestOneInput` per binary, so swift-fuzz dispatches between them at
// startup: `swift package fuzz <name>` sets FUZZ_TARGET, and the generated
// entry point selects from the registry.
//
// Sharing an executable means one build instead of several, at the cost of a
// binary instrumented for all of them. Each target still gets its own
// Seeds/Corpus/Crashes directories, keyed by name.
let fuzzTargets: @Sendable () -> Void = {
    unsafe FuzzTarget("Forwards") { bytes in
        try? BuggyLibrary.parse(unsafe Array(bytes))
    }

    unsafe FuzzTarget("Backwards") { bytes in
        // A deliberately different view of the same input, so the two targets
        // are not interchangeable.
        try? BuggyLibrary.parse(Array((unsafe Array(bytes)).reversed()))
    }
}
