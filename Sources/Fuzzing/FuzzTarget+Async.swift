import Dispatch

extension FuzzTarget {
    /// Creates and registers a fuzz target whose body is asynchronous.
    ///
    /// ```swift
    /// FuzzTarget.async("Routing") { bytes in
    ///     _ = try? await app.testable().sendRequest(makeRequest(bytes))
    /// }
    /// ```
    ///
    /// libFuzzer's entry point is a synchronous C function that must run one
    /// input and return, so there is nowhere to `await`. This bridges the gap:
    /// the body runs on a detached `Task` and the calling thread blocks until it
    /// finishes. Blocking is safe here because libFuzzer calls us on its own
    /// thread, not on a cooperative-pool thread, so nothing the `Task` needs is
    /// being held up.
    ///
    /// ### The body must not require the main actor
    ///
    /// libFuzzer runs the entry point on the process's main thread, and this
    /// blocks it. Work isolated to `@MainActor` is scheduled on that same
    /// thread, so it would wait for a thread that is waiting for it — a
    /// deadlock. Server-side code (Vapor, NIO) is not main-actor-isolated and
    /// is unaffected; UI-layer code is not fuzzable this way.
    ///
    /// The closure being `@Sendable` already stops it *inheriting* main-actor
    /// isolation from where it is written, which is the silent way to get here.
    /// What no attribute can prevent is an explicit hop inside the body — an
    /// `await MainActor.run { }` — so a stalled execution is reported after
    /// `FuzzRunner.asyncTimeout` seconds rather than hanging for ever.
    ///
    /// ### Cost
    ///
    /// A `Task` and a semaphore per input, plus a copy of the bytes so they can
    /// cross into the task safely. That is a few microseconds, which is
    /// invisible against real asynchronous work but would dominate a body that
    /// only parses a few bytes — use ``init(_:_:)`` or ``structured(_:_:)`` for
    /// those.
    ///
    /// - Note: The bytes are copied, so unlike the synchronous forms the body
    ///   may keep them.
    @discardableResult
    public static func async(
        _ name: String,
        _ body: @escaping @Sendable ([UInt8]) async -> Void
    ) -> FuzzTarget {
        unsafe FuzzTarget(name: name, unsafeBytes: { buffer in
            let bytes = unsafe [UInt8](buffer)
            runBlocking { await body(bytes) }
        })
    }

    /// An asynchronous fuzz target that reads typed values.
    ///
    /// The provider is passed by value rather than `inout`, because an `inout`
    /// argument cannot be held across a suspension point. Rebind it and use it
    /// as normal:
    ///
    /// ```swift
    /// FuzzTarget.structuredAsync("Routing") { data in
    ///     var data = data
    ///     let method = data.caseOf(HTTPMethod.self) ?? .GET
    ///     _ = try? await app.handle(method, body: data.remainingBytes())
    /// }
    /// ```
    ///
    /// The same main-actor and cost caveats as ``async(_:_:)`` apply.
    @discardableResult
    public static func structuredAsync(
        _ name: String,
        _ body: @escaping @Sendable (FuzzedDataProvider) async -> Void
    ) -> FuzzTarget {
        Self.async(name) { bytes in
            await body(FuzzedDataProvider(bytes))
        }
    }
}

/// Runs `operation` to completion, blocking the caller.
///
/// Deliberately not general-purpose: it is correct only because libFuzzer calls
/// the fuzz entry point on a thread that owns nothing the operation needs.
private func runBlocking(_ operation: @escaping @Sendable () async -> Void) {
    let finished = DispatchSemaphore(value: 0)
    Task.detached(priority: .userInitiated) {
        await operation()
        finished.signal()
    }
    guard finished.wait(timeout: .now() + .seconds(FuzzRunner.asyncTimeout)) == .success else {
        FuzzRunner.reportStall()
    }
}
