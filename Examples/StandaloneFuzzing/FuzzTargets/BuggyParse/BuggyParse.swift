import BuggyLibrary
import Fuzzing

let fuzzTargets: @Sendable () -> Void = {
    FuzzTarget("BuggyParse") { bytes in
        try? BuggyLibrary.parse(bytes)
    }
}
