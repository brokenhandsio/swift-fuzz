import Foundation

/// Everything `swift package fuzz` accepts.
struct Arguments {
    enum Mode {
        /// Normal coverage-guided fuzzing.
        case fuzz
        /// Run the existing corpus once and exit. For CI regression runs.
        case replay
        /// Run a single saved input, usually a crash artefact.
        case reproduce(String)
    }

    var target: String?
    var mode: Mode = .fuzz
    var release = false
    var sanitizers = "fuzzer,address"
    /// Flags handed straight to libFuzzer, after our defaults so they win.
    var passthrough: [String] = []

    static func parse(_ arguments: [String]) throws -> Arguments {
        var result = Arguments()
        var index = arguments.startIndex

        func next(_ flag: String) throws -> String {
            index += 1
            guard index < arguments.endIndex else {
                throw FuzzError("\(flag) requires a value.")
            }
            return arguments[index]
        }

        while index < arguments.endIndex {
            let argument = arguments[index]
            switch argument {
            case "--help", "-h":
                throw FuzzError(usage)
            case "--time":
                result.passthrough.append("-max_total_time=\(try next("--time"))")
            case "--replay":
                result.mode = .replay
            case "--reproduce":
                result.mode = .reproduce(try next("--reproduce"))
            case "--jobs":
                result.passthrough.append("-jobs=\(try next("--jobs"))")
            case "--release":
                result.release = true
            case "--sanitizers":
                result.sanitizers = try next("--sanitizers")
            case "--no-asan":
                result.sanitizers = "fuzzer"
            default:
                if argument.hasPrefix("-") {
                    // libFuzzer's own flags (-max_len, -rss_limit_mb, -dict, ...).
                    result.passthrough.append(argument)
                } else if result.target == nil {
                    result.target = argument
                } else {
                    throw FuzzError("Unexpected argument \"\(argument)\".")
                }
            }
            index += 1
        }
        return result
    }

    static let usage = """
        USAGE: swift package --allow-writing-to-package-directory fuzz <target> [options]

        OPTIONS:
          --time <seconds>     Stop after this many seconds (-max_total_time).
          --jobs <n>           Run n fuzzing processes in parallel.
          --replay             Run the existing corpus once and exit. For CI.
          --reproduce <path>   Run one saved input, usually a crash artefact.
          --release            Build in release configuration.
          --sanitizers <list>  Override the sanitizer set. Default: fuzzer,address
          --no-asan            Shorthand for --sanitizers fuzzer.
          --help               Show this message.

        Any other -flag is passed straight through to libFuzzer, so -max_len=64,
        -rss_limit_mb=4096, -dict=... and friends all work.
        """
}

struct FuzzError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}
