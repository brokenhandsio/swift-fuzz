import Foundation

extension Process {
    /// Runs a tool with an environment and returns its standard output, or nil
    /// if it exited non-zero.
    static func captureOutput(
        _ executable: URL, _ arguments: [String], environment: [String: String]
    ) throws -> String? {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.environment = environment
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { return nil }
        return String(decoding: data, as: UTF8.self)
    }

    /// Runs a tool and returns its standard output, ignoring a non-zero exit.
    static func capture(_ executable: URL, _ arguments: [String]) throws -> String {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return String(decoding: data, as: UTF8.self)
    }

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

extension Process {
    /// Runs a tool with its output discarded and returns its exit status.
    static func status(_ executable: URL, _ arguments: [String]) throws -> Int32 {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        process.waitUntilExit()
        return process.terminationStatus
    }
}

extension Process {
    /// Runs a tool and returns its exit status together with everything it
    /// wrote to standard error.
    ///
    /// libFuzzer writes all of its diagnostics — progress, coverage dumps,
    /// crash reports — to standard error, so that is the interesting stream.
    /// Standard output is discarded rather than piped: nothing useful arrives
    /// on it, and an unread pipe would deadlock a chatty fuzz target.
    static func captureDiagnostics(
        _ executable: URL,
        _ arguments: [String],
        environment: [String: String],
        currentDirectory: URL
    ) throws -> (status: Int32, diagnostics: String) {
        let process = Process()
        process.executableURL = executable
        process.arguments = arguments
        process.environment = environment
        process.currentDirectoryURL = currentDirectory
        let pipe = Pipe()
        process.standardError = pipe
        process.standardOutput = FileHandle.nullDevice
        try process.run()
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        let status = process.terminationReason == .uncaughtSignal
            ? 128 + process.terminationStatus
            : process.terminationStatus
        return (status, String(decoding: data, as: UTF8.self))
    }
}
