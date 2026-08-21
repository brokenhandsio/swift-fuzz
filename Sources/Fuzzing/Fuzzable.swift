/// A type that can be built from fuzzer-produced input.
///
/// Conforming lets a harness ask for a value directly instead of decoding one
/// by hand:
///
/// ```swift
/// struct Request: Fuzzable {
///     var method: Method
///     var path: String
///
///     init(from provider: inout FuzzedDataProvider) {
///         method = provider.caseOf() ?? .get
///         path = provider.value()
///     }
/// }
///
/// FuzzTarget.structured("Router") { data in
///     _ = router.route(data.value(Request.self))
/// }
/// ```
///
/// ### Why this cannot fail
///
/// `init(from:)` is not throwing or failable, and it must always produce a
/// value. The provider yields zeros once the input is exhausted, which happens
/// constantly — a fuzzer spends most of its time on very short inputs. A
/// failable initialiser would turn that into an error path taken by the
/// majority of executions, and a harness that returns early on short input
/// stops exercising the code it was written for.
///
/// Draw on the provider in a fixed order, without branching on how much is
/// left. The same bytes should always produce the same value, so that a saved
/// crashing input still reproduces.
public protocol Fuzzable {
    /// Builds a value by consuming from `provider`.
    init(from provider: inout FuzzedDataProvider)
}

// MARK: - Standard library conformances

extension Bool: Fuzzable {
    public init(from provider: inout FuzzedDataProvider) {
        self = provider.bool()
    }
}

extension String: Fuzzable {
    /// Consumes a length-prefixed chunk as UTF-8 text, repairing invalid
    /// sequences.
    ///
    /// Repairing rather than rejecting keeps the initialiser total, and the
    /// replacement characters are themselves worth testing — text handling
    /// frequently goes wrong on them.
    ///
    /// Bounded, not greedy. A `Fuzzable` value has to compose: a greedy string
    /// consumes the whole input, so every field declared after one gets zeros
    /// forever and `[String]` yields one populated element followed by empties.
    /// The bound is ``FuzzedDataProvider/chunk()``'s, for the reason its own
    /// documentation gives — one byte of input must not be able to starve
    /// everything drawn after it.
    ///
    /// When a target genuinely wants the rest of the input as text, and it is
    /// the last thing it draws, ask for that directly with
    /// ``FuzzedDataProvider/remainingText()``.
    public init(from provider: inout FuzzedDataProvider) {
        self = provider.text()
    }
}

extension Array: Fuzzable where Element: Fuzzable {
    /// Consumes a length, then that many elements.
    ///
    /// The length is bounded twice: at 255, so a single byte of input cannot
    /// ask for an enormous allocation — the fuzzer would otherwise spend its
    /// time on out-of-memory reports rather than on the code under test — and
    /// at what is left, so a short input cannot ask for two hundred elements it
    /// has no bytes to fill.
    public init(from provider: inout FuzzedDataProvider) {
        let limit = UInt8(clamping: provider.remainingCount)
        let count = Int(provider.integer(in: UInt8(0)...limit))
        var elements: [Element] = []
        elements.reserveCapacity(Swift.min(count, 64))
        for _ in 0..<count {
            elements.append(Element(from: &provider))
        }
        self = elements
    }
}

extension Optional: Fuzzable where Wrapped: Fuzzable {
    public init(from provider: inout FuzzedDataProvider) {
        self = provider.bool() ? Wrapped(from: &provider) : nil
    }
}

// Integers and floats consume their own width from the input.
extension Int: Fuzzable { public init(from p: inout FuzzedDataProvider) { self = p.integer() } }
extension Int8: Fuzzable { public init(from p: inout FuzzedDataProvider) { self = p.integer() } }
extension Int16: Fuzzable { public init(from p: inout FuzzedDataProvider) { self = p.integer() } }
extension Int32: Fuzzable { public init(from p: inout FuzzedDataProvider) { self = p.integer() } }
extension Int64: Fuzzable { public init(from p: inout FuzzedDataProvider) { self = p.integer() } }
extension UInt: Fuzzable { public init(from p: inout FuzzedDataProvider) { self = p.integer() } }
extension UInt8: Fuzzable { public init(from p: inout FuzzedDataProvider) { self = p.integer() } }
extension UInt16: Fuzzable { public init(from p: inout FuzzedDataProvider) { self = p.integer() } }
extension UInt32: Fuzzable { public init(from p: inout FuzzedDataProvider) { self = p.integer() } }
extension UInt64: Fuzzable { public init(from p: inout FuzzedDataProvider) { self = p.integer() } }

extension Double: Fuzzable {
    /// Built from a bit pattern, so NaNs, infinities and subnormals all occur —
    /// which is the point.
    public init(from provider: inout FuzzedDataProvider) {
        self = Double(bitPattern: provider.integer(UInt64.self))
    }
}

extension Float: Fuzzable {
    public init(from provider: inout FuzzedDataProvider) {
        self = Float(bitPattern: provider.integer(UInt32.self))
    }
}
