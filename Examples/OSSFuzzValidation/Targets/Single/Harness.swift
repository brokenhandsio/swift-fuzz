import Fuzzing

let fuzzTargets: @Sendable () -> Void = {
    FuzzTarget.structured("Single") { data in
        let choice = data.element(of: [0, 1, 2])
        if choice == 1 { _ = data.optionalText() }
        _ = data.remainingBytes()
    }
}
