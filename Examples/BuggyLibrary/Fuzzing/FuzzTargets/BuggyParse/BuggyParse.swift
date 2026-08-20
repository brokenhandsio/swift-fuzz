import BuggyLibrary
import Fuzzing

let fuzzTargets: @Sendable () -> Void = {
    unsafe FuzzTarget("BuggyParse") { bytes in
        // The one unsafe step, and the only one a typical harness needs: copy
        // the fuzzer's buffer into a value the library can take. `bytes` is
        // valid only for this call, so anything kept must be copied anyway.
        //
        // `unsafe` is required here because this package enables
        // `.strictMemorySafety()`; without that setting it is just `Array(bytes)`.
        try? BuggyLibrary.parse(unsafe Array(bytes))
    }
}
