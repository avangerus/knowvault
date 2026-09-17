# KnowVault document-parser worker third-party notices

This notice is part of the R-16 release package. The final OCI stage is built
from `scratch`; it contains the jlink runtime, the application/JAR closure and
the one native `libc6` loader package listed in `sbom.spdx.json`.

## Eclipse Temurin OpenJDK runtime 21.0.12+8

License: `GPL-2.0-only WITH Classpath-exception-2.0`.

The exact source offer is pinned to OpenJDK update commit
`9de4f68c88a0a1510373f291d1a95b1f6b0db8c8`:

<https://github.com/openjdk/jdk21u/tree/9de4f68c88a0a1510373f291d1a95b1f6b0db8c8>

The corresponding source archive is:

<https://github.com/openjdk/jdk21u/archive/9de4f68c88a0a1510373f291d1a95b1f6b0db8c8.tar.gz>

The machine-readable offer and the exact jlink module set are in
`source-compliance/openjdk-temurin-21.0.12+8/SOURCE-OFFER.json`.

## libc6 native launcher closure

The JVM launcher needs a dynamic loader. Only the amd64 `libc6` package
`2.39-0ubuntu8.8` is copied into the scratch image; no package manager,
distribution metadata or other Ubuntu package is shipped.

License: `LGPL-2.1-or-later`.

Source offer: <https://launchpad.net/ubuntu/+source/glibc/2.39-0ubuntu8.8>

## Apache POI runtime closure

The following runtime artifacts are copied from the checksum-locked Maven
closure. Apache artifacts are Apache-2.0; `curvesapi` is BSD-3-Clause.
Apache POI 5.5.1 is the selected Office parser distribution.

| Coordinate | Version | License |
| --- | --- | --- |
| `org.apache.poi:poi` | 5.5.1 | Apache-2.0 |
| `org.apache.poi:poi-ooxml` | 5.5.1 | Apache-2.0 |
| `org.apache.poi:poi-ooxml-lite` | 5.5.1 | Apache-2.0 |
| `org.apache.xmlbeans:xmlbeans` | 5.3.0 | Apache-2.0 |
| `org.apache.commons:commons-collections4` | 4.5.0 | Apache-2.0 |
| `org.apache.commons:commons-math3` | 3.6.1 | Apache-2.0 |
| `org.apache.commons:commons-compress` | 1.28.0 | Apache-2.0 |
| `commons-codec:commons-codec` | 1.20.0 | Apache-2.0 |
| `commons-io:commons-io` | 2.21.0 | Apache-2.0 |
| `org.apache.commons:commons-lang3` | 3.18.0 | Apache-2.0 |
| `com.zaxxer:SparseBitSet` | 1.3 | Apache-2.0 |
| `com.github.virtuald:curvesapi` | 1.08 | BSD-3-Clause |
| `org.apache.logging.log4j:log4j-api` | 2.25.5 | Apache-2.0 |

`org.apache.logging.log4j:log4j-core` is not in the closure and is forbidden
by the dependency lock. KnowVault's own worker artifact is an internal product
artifact and is recorded separately in the SPDX document.

## Apache PDFBox runtime closure

Apache PDFBox 3.0.8 is the selected text-PDF observer. Its four-artifact
runtime closure is Apache-2.0 and checksum-locked with the POI closure.

| Coordinate | Version | License |
| --- | --- | --- |
| `org.apache.pdfbox:pdfbox` | 3.0.8 | Apache-2.0 |
| `org.apache.pdfbox:pdfbox-io` | 3.0.8 | Apache-2.0 |
| `org.apache.pdfbox:fontbox` | 3.0.8 | Apache-2.0 |
| `commons-logging:commons-logging` | 1.4.0 | Apache-2.0 |
