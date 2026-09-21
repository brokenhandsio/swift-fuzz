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
        /// Reduce the corpus using the current build's observed features.
        case minimizeCorpus
        /// Shrink one crashing input to the smallest input that still crashes.
        case minimizeCrash(String)
        /// Report which parts of the code under test the corpus reaches.
        case coverage
        /// Print the fuzz targets this package registers, and exit.
        case list
    }

    var target: String?
    var mode: Mode = .fuzz
    var release = false
    var sanitizers = "fuzzer,address"
    /// Flags handed straight to libFuzzer, after our defaults so they win.
    var passthrough: [String] = []
    /// Whether a coverage report should name every function it did not reach.
    var listUncovered = false
    /// Whether a coverage report should include files from dependencies.
    var includeDependencies = false

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
            case "--list":
                result.mode = .list
            case "--replay":
                result.mode = .replay
            case "--coverage":
                result.mode = .coverage
            case "--uncovered":
                // Implies --coverage: the listing is part of that report, and
                // asking for it without asking for coverage cannot mean
                // anything else.
                result.mode = .coverage
                result.listUncovered = true
            case "--include-dependencies":
                result.includeDependencies = true
            case "--minimize-corpus":
                result.mode = .minimizeCorpus
            case "--minimize-crash":
                result.mode = .minimizeCrash(try next("--minimize-crash"))
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
          --list               Print the fuzz targets this package registers.
          --replay             Run the existing corpus once and exit. For CI.
          --coverage           Report which source files the corpus reaches, and
                               how much of each. Runs the corpus once; mutates
                               nothing.
          --uncovered          As --coverage, and additionally name every
                               function the corpus never reached.
          --include-dependencies
                               Include dependency source files in the coverage
                               report. By default it covers only the package
                               under test.
          --minimize-corpus    Reduce the corpus using this build's observed
                               features. Seeds are never modified.
          --minimize-crash <path>
                               Shrink one crashing input in place to the smallest
                               input that still crashes.
          --reproduce <path>   Run one saved input, usually a crash artefact.
          --release            Build in release configuration.
          --sanitizers <list>  Override the sanitizer set. Default: fuzzer,address
          --no-asan            Shorthand for --sanitizers fuzzer.
          --help               Show this message.

        Any other -flag is passed straight through to libFuzzer, so -max_len=64,
        -rss_limit_mb=4096, -dict=... and friends all work.

        On macOS, --coverage also needs --disable-sandbox: SwiftPM's plugin
        sandbox stops the sanitizer runtime launching llvm-symbolizer, which
        coverage needs to name what it found. Linux needs nothing extra.
        """
}

struct FuzzError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}
