import Foundation
import Fuzzing

func check(_ bytes: [UInt8]) {
    let marker = Bundle.module.url(forResource: "marker", withExtension: "txt")!
    precondition((try? String(contentsOf: marker, encoding: .utf8)) == "resource-ok\n")
    // Only the explicit reproduction check supplies this synthetic input.
    precondition(bytes != Array("swift-fuzz-crash".utf8), "planted export crash")
    _ = try? JSONSerialization.jsonObject(with: Data(bytes), options: .fragmentsAllowed)
}

let fuzzTargets: @Sendable () -> Void = {
    FuzzTarget.bytes("Decode") { check($0) }
    FuzzTarget.async("AsyncDecode") { bytes in
        await Task.yield()
        check(bytes)
    }
}
