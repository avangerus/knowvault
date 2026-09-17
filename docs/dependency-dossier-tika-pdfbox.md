# Apache Tika and direct POI/PDFBox: decision evidence

This summary preserves the 2026-07-23 assessment cited by
[ADR-0062](adr/0062-isolated-document-parser-worker-accepted.md). It is a decision
record, not a current release qualification or a new dependency proposal.

## Accepted decision

Tika was rejected as the universal extraction API because its text/XHTML output
does not provide the exact structural anchors required by
[Parser contracts](PARSER_CONTRACTS.md). ADR-0062 selected a separate, isolated
worker using Apache POI directly for DOCX/PPTX/XLSX and Apache PDFBox directly
for text PDF. Tika is not used as an abstraction layer.

The original assessment proposed a pure-Go alternative; that recommendation
was **not adopted**. Any replacement must independently demonstrate equivalent
anchor accuracy, determinism and safety on the same adversarial corpus. A
smaller dependency graph alone is not qualification.

## Technical basis

- Tika exposes coarse PDF page wrappers but not the glyph coordinates needed
  for exact citations. PDFBox's lower-level `TextPosition` API exposes geometry.
- Tika's OOXML paragraph output carries formatting/nesting rather than stable
  paragraph indices, original element identifiers or character offsets.
- Its XLSX output uses cell references internally to arrange a table, but does
  not preserve A1 references as addressable output anchors.
- Text PDF has no inherent paragraph model: paragraphs derived from glyph or
  word geometry remain an extraction interpretation, whichever library is used.

The assessment's primary sources were Tika's
[PDF XHTML implementation](https://github.com/apache/tika/blob/main/tika-parsers/tika-parsers-standard/tika-parsers-standard-modules/tika-parser-pdf-module/src/main/java/org/apache/tika/parser/pdf/AbstractPDF2XHTML.java),
[OOXML handler API](https://tika.apache.org/3.2.3/api/org/apache/tika/parser/microsoft/ooxml/OOXMLTikaBodyPartHandler.html),
and PDFBox's [TextPosition API](https://pdfbox.apache.org/docs/2.0.13/javadocs/org/apache/pdfbox/text/TextPosition.html).
These references explain the historical decision; mutable upstream pages do
not establish the identity or qualification of a shipped artifact.

## Licensing and security limits

The assessed Office/PDF subset had a permissive Java dependency path, but that
did not approve the entire Tika distribution or a JVM image. Optional modules
introduced separate concerns: `jhighlight` included an unresolved LGPL/CDDL
review; `junrar` carried the UnRAR restriction; JPEG2000 support involved an
excluded field-of-use dependency. Such modules cannot be silently added to the
selected closure. Distribution must preserve applicable LICENSE and NOTICE
material. The original sources include Tika 3.3.2's
[LICENSE](https://github.com/apache/tika/blob/3.3.2/LICENSE.txt),
[NOTICE](https://github.com/apache/tika/blob/3.3.2/NOTICE.txt), and the
[ASF licensing policy](https://www.apache.org/legal/resolved.html).

OpenJDK and native runtime components are separate from the permissive Java
library closure. [ADR-0066](adr/0066-parser-runtime-license-decoupling-accepted.md)
governs the selected `scratch`/`jlink` construction and the exact Classpath-
exception/native-runtime source and notice obligations; a general-purpose JRE
base is not interchangeable with that reviewed artifact.

Recurring parser risks include XXE, decompression/entity bombs, malformed
font/image structures and unbounded CPU or memory consumption. Tika's network
server also had SSRF/RCE exposure; rejecting Tika does not remove the need to
harden the selected POI/PDFBox parsers. The worker must retain the accepted
isolation, no-network operation, input/output/resource bounds, active/encrypted
input refusal and content-free error handling. Example applications such as
`pdfbox-examples` and an unreviewed logging backend are outside the selected
runtime closure.

Historical CVE assessments do not establish present safety. Requalification
uses the exact image and transitive SBOM, a dated vulnerability database,
applicable notices/source offer and deterministic rebuild evidence. See the
[parser qualification record](qualification-s2b-document-parser.md),
[dependency lock](../workers/document-parser/dependencies.lock.json) and
[release artifacts](../workers/document-parser/release/). No unresolved image
digest or proposed alternative from the original research is treated as a
qualified dependency.
