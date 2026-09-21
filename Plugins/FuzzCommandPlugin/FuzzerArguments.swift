/// Runtime defaults shared by fuzzing, replay, coverage and minimization.
enum FuzzerArguments {
    static func defaults(layout: Layout) -> [String] {
        var arguments = [
            "-artifact_prefix=\(layout.crashes.path)/",
            "-detect_leaks=0",
            "-use_value_profile=1",
        ]
        if let dictionary = layout.dictionary {
            arguments.append("-dict=\(dictionary.path)")
        }
        return arguments
    }
}
