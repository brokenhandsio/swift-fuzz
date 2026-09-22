# Input compatibility

Keep saved inputs meaningful as a harness and its dependencies evolve.

## The 1.x contract

During 1.x, ``FuzzedDataProvider`` preserves decoded values and byte consumption
for the same bytes, sequence of operations and arguments. This includes the
standard ``Fuzzable`` conformances. Behavior-changing decoding revisions belong
in a major version or an explicitly selected new API, rather than a transparent
optimization. Literal fixtures in `DecodingCompatibilityTests.swift` guard this
contract.

The harness also defines the format. Reordering fields, changing bounds, adding
enum cases, reordering a collection or changing a custom `Fuzzable` initializer
can change saved inputs. Use explicitly sized integers such as `UInt32` when
inputs must work across different machine word sizes; `Int` and `UInt` use the
platform's width. Collection selection depends on the count and iteration order,
so do not rely on unordered collections such as `Set` for stable choices.

## Byte rules

Payload bytes come from the front. Control values come from the back; the first
byte taken is the most significant byte of the value. Short control inputs are
not padded. For example, `[0x12, 0x34]` read as a `UInt32` produces `0x3412`.

| Operation | Consumption and mapping |
| --- | --- |
| `bytes(n)` | Up to `max(0, n)` bytes from the front, bounded by the remaining input. |
| `remainingBytes()`, `remainingText()` | All remaining bytes from the front. Text repairs invalid UTF-8. |
| `integer(T.self)` | Up to `MemoryLayout<T>.size` bytes from the back; an exhausted input produces zero. |
| `integer(in:)` | The type's full width, bounded by available input; reduces modulo the range size and adds the lower bound. A full-width range uses the raw bit pattern. A single-value range consumes nothing. |
| `bool()` | One byte from the back; its low bit decides the result. Exhaustion is `false`. |
| `probability()` | A `UInt64` divided by `UInt64.max` as `Double`. |
| `chunk()`, `text()` | A `UInt16` length drawn in `0...min(remainingCount, 65_535)`, with that bound measured before consuming the length, then that many bytes from the front, truncated to what remains. Text repairs invalid UTF-8. |
| `element(of:)`, `caseOf()` | The minimum bytes needed to represent `count - 1`, bounded by available input; reduce modulo the count. Empty collections return `nil` and singleton collections return their sole element without consuming bytes. Exhaustion selects the first element of a nonempty collection. |
| `optionalText()` | A `bool()` presence flag; only when true, consume `text()`. Matches `value(String?.self)`. |
| `value(T.self)` | The standard scalar conformances use the corresponding operations above. `Float` and `Double` use `UInt32` and `UInt64` bit patterns. Custom conformances define their own sequence. |
| `value([T].self)` | A `UInt8` count drawn in `0...min(remainingCount, 255)`, bounded before consuming the count, then that many `T` values. |
| `value(T?.self)` | A `bool()` presence flag, then a `T` value only when present. |

Modulo mapping is biased toward smaller offsets unless the range size divides
the number of possible control values. These methods consume a predictable
number of bytes rather than retrying to obtain an unbiased sample.

For `element(of: ["a", "b", "c"])`, `[0xAA, 0xBB, 0x02]` selects `"c"` and
leaves `[0xAA, 0xBB]`. Selection needs one byte for 2...256 choices, two for
257...65,536, three for 65,537...16,777,216, and so on.

For `optionalText()`:

| Input bytes | Value | Remaining bytes |
| --- | --- | --- |
| `[]` | `nil` | `[]` |
| `[0x41, 0x00]` | `nil` | `[0x41]` |
| `[0x01]` | `""` | `[]` |
| `[0x41, 0x01, 0x00, 0x01]` | `"A"` | `[]` |

## Migrating from 0.4.x

Two operations change in preparation for 1.0:

- `element(of:)` and `caseOf()` previously consumed up to eight bytes for any
  nontrivial selection. They now consume only the width required by the count.
- `optionalText()` previously consumed a chunk and mapped an empty chunk to
  `nil`. It now consumes a separate presence flag and can also produce a present
  empty string.

These changes also affect every field read after those operations. Public call
signatures are unchanged, but saved inputs are not automatically translated.
The ownership change does not alter decoding, and harnesses that do not use
either changed operation retain their prior decoding behavior.

Before upgrading, keep a copy of important inputs and the old harness revision,
dependency version and toolchain needed to interpret them. Capture the decoded
values of important reproductions. Under the new decoder, verify that each
regression input still exercises the intended case; translate its framing using
the harness's format, or test the captured values directly in an ordinary unit
test. A harness-specific encoder can help, but there is no universal conversion:
the provider does not know the order, bounds or branches a harness uses.

Retain an old working corpus separately while starting or migrating the new
one, and refresh CI corpus caches or target names when their input format
changes. Minimization recomputes useful inputs for the current build; it does
not restore the old meaning of an input. Passing replay alone also does not
prove that a translated regression input exercises the original case.
