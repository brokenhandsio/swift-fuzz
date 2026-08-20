import BuggyLibrary
import Fuzzing

let fuzzTargets: @Sendable () -> Void = {
    FuzzTarget("BuggyParse") { bytes in
        // `bytes` is a Span<UInt8>: bounds-checked, and the compiler enforces
        // that it does not outlive this call. Passed straight through, so there
        // is nothing to copy.
        try? BuggyLibrary.parse(bytes)
    }
}
