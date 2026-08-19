import Foundation

extension Process {
    /// Runs a tool with its output attached to ours, and returns its exit status.
    ///
    /// Fuzzing output is the point of the exercise, so it is streamed rather
    /// than captured.
    @discardableResult
    static func stream(
        _ executable: URL,
        _ arguments: [String],
        environment: [String: String],
        currentDirectory: URL
    ) throws -> Int32 {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.environment = environment
        process.currentDirectoryURL = currentDirectory
        try process.run()
        process.waitUntilExit()
        // A tool killed by a signal reports terminationStatus 0 with reason
        // .uncaughtSignal; libFuzzer's own crashes come back as a normal exit
        // code, but a hard SIGKILL (OOM) would otherwise look like success.
        if process.terminationReason == .uncaughtSignal {
            return 128 + process.terminationStatus
        }
        return process.terminationStatus
    }
}
