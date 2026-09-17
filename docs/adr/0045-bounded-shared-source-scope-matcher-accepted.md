# ADR-0045: Bounded shared source scope matcher

Status: accepted.

Folder, Git and Site path authorization uses the single Go package
`internal/source/scopeglob` and the exact grammar version `scope-glob-v1`.
Control-plane validation and every connector runtime must call that package;
`path.Match`, `filepath.Match` and connector-local glob engines are forbidden.
The contract runner is built inside the root Go module and imports the same
package; it does not retain a second validation or matching grammar.

Inputs are relative NFC UTF-8 paths with `/` separators. The grammar has only
literal code points, segment-local `*` and `?`, and whole-segment `**`. Empty,
dot and parent segments, backslashes, escapes, negation, classes, braces,
extglob, embedded globstars, controls and trailing pattern whitespace fail
closed. Exclude matches always win. An empty include list means the approved
root, not an unbounded source outside that root.

Limits are 128 include and 128 exclude patterns, 4,096 bytes and 256 segments
per pattern or path. One Match call shares a deterministic 4,194,304-step
budget across all patterns. Budget exhaustion is a typed denial. The zero value,
nil matcher and unrecognised case mode also fail closed. A matcher becomes valid
only through Compile and is immutable afterward.

POSIX, Git and object paths are case-sensitive. WINDOWS comparison uses pinned
Go `strings.EqualFold`; it does not rewrite the actual path later opened by the
connector. Windows drive-qualified, drive-relative and NTFS alternate-stream
forms, trailing dot/space and case-insensitive device names are rejected
independently of the host OS. Both binaries run the same canonical golden
vectors, and the matcher version remains part of the immutable source-scope
configuration hash.

The architecture guard protects the package and rejects alternate standard
library glob calls in source and connector production code. No new dependency
is introduced: Unicode NFC uses the already licensed and locked `x/text` module.
