# Third-party notices and release boundary

This inventory belongs to the locally built `knowvault-tesseract-ocr:gauntlet-20260829-v3`
candidate. It is evidence for review, not a claim that the candidate is
approved for production. The complete machine-readable package inventory and
the observed license fields are in `sbom.spdx.json`; package copyright files
remain under `/usr/share/doc` in the image.

## Runtime components

| Component | Exact identity | License evidence in image |
| --- | --- | --- |
| Python runtime | `python:3.12.14-slim-bookworm@sha256:0f5b26b9518d002b6173fd61daad821fa340635ebfec5bba471013f9ca114579` | `/usr/share/doc/python3.12/copyright` and SBOM |
| Tesseract engine and CLI | Debian `5.3.0-2`, archive SHA-256 recorded in `../debian-packages.lock.json` | `/usr/share/doc/tesseract-ocr/copyright`, `/usr/share/doc/libtesseract5/copyright` |
| English tessdata | Debian `1:4.1.0-2`, artifact SHA-256 `7d4322bd2a7749724879683fc3912cb542f19906c83bcc1a52132556427170b2` | `/usr/share/doc/tesseract-ocr-eng/copyright` |
| Leptonica | Debian `1.82.0-3+b3`, archive SHA-256 recorded in the package lock | `/usr/share/doc/liblept5/copyright` |
| Remaining native dependencies | Exact Debian `bookworm` `amd64` package versions and archive hashes in `../debian-packages.lock.json` | Each package's `/usr/share/doc/<package>/copyright` and SBOM |

The Tesseract and tessdata Debian copyright files identify their upstream
Apache-2.0 notices. Leptonica and all transitive dependencies must be reviewed
from the image copyright files and SBOM before redistribution; this file does
not replace those notices.

## Evidence files

* `sbom.spdx.json` was produced by Syft `anchore/syft:v1.48.0@sha256:b4f1df79f97b817682d8b5ff941eb6bfe74f6172553a5e312c75bbc2eabc405c`.
* `grype.json` was produced by Grype `anchore/grype:v0.116.0@sha256:fd4ab4d1042b522c896e73bdf09ab8bf384fa417df99d6dd0d6e1008c7e7c821`.
* `image-lock.json` records the v3 candidate image and all observed artifact
  digests. The security gate remains failed because the fresh scan still has
  Critical/High findings; the normalized no-cache OCI pair passes
  reproducibility, but offline repository approval is still required.

The Dockerfile currently obtains Debian metadata from the live
`deb.debian.org` Bookworm mirrors. The package archive hashes are checked in
the build, but an offline/snapshot repository is still required for a
production reproducibility claim.
