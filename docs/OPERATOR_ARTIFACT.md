# knowvault-operator supply artifact

`knowvault-operator` is delivered as the pinned scratch image defined by
`deploy/images/Dockerfile.operator`. The image is a one-shot deployment tool,
not a long-running application service. It contains exactly the static
operator binary, the versioned `db/migrations/` stream, and
`/usr/share/knowvault/operator-artifact.json`.

## Build

Run the build from the repository root with the exact toolchain and explicit
release identity:

```text
docker build \
  --provenance=false \
  --platform linux/amd64 \
  --file deploy/images/Dockerfile.operator \
  --tag knowvault-operator:0.1.0 \
  --build-arg VERSION=0.1.0 \
  --build-arg REVISION=<source-commit> \
  --build-arg BUILT_AT=<fixed-utc-timestamp> \
  --build-arg SOURCE_DATE_EPOCH=1704067200 \
  .
```

The release target is pinned to `linux/amd64`; that platform and the builder
reference are both recorded in `architecture/versions.json` and the Dockerfile
defaults. The Dockerfile-specific ignore file admits only
`go.mod`, `go.sum`, `cmd/operator`, `internal`, and `db/migrations`; the
repository-wide ignore intentionally keeps `db/` out of other application
images.

`--provenance=false` plus the locked `SOURCE_DATE_EPOCH` makes the OCI image
manifest deterministic when the source, `VERSION`, `REVISION`, and fixed
`BUILT_AT` are held constant; the generated
identity record and the separately required SPDX/Syft attestation provide the
release provenance instead of an unreviewed, builder-generated attestation.

The builder warms the checksum-locked Go module cache once. Compilation,
migration closure copying, and identity generation all run with
`RUN --network=none`; a missing module or input fails closed instead of being
downloaded during those steps. The final stage is `scratch` and has no shell
or package manager. The one-shot operator runs as numeric `0:0` because its
published mount contract requires root-owned files with group `65532`;
`secrets generate` must therefore be able to assign that group. This is not a
long-running application identity. Keep the root filesystem read-only, drop
every capability by default, and add only `CHOWN` for the `secrets generate`
invocation. Other subcommands need no runtime write path or added capability.

## Artifact identity and SBOM

The generated `operator-artifact.json` records the SHA-256 of the exact
operator binary, the ordered named migration set, and their derived
`knowvault-operator-artifact-v1` identity. Its SBOM hook binds to the
`artifact_identity` field. `BUILT_AT` is provenance only and is not included
in that content identity. Rebuilding identical source, lock and `VERSION`
therefore produces the same identity.

The `sbom` object is an attestation hook, not an empty or synthetic SBOM.
Release tooling must run the locked Syft `1.48.0` binary against the final
image and publish `knowvault-operator.sbom.spdx.json` bound to the recorded
identity. A release is incomplete while the hook says
`RELEASE_ATTESTATION_REQUIRED`.

Before publishing, compare the reproducible OCI image digest, generated
identity and binary/migration digests with the `operator_artifact` record in
`architecture/versions.json`.
Changing the operator source, migration stream, builder digest, or release
version requires a new lock entry and a new artifact identity.

After the runtime source is frozen, this read-only extraction prints the exact
values to carry into the lock and its checker expectation (it does not rewrite
protected files):

```text
$tag = 'knowvault-operator:0.1.0'
$container = docker create $tag
$artifactPath = Join-Path $env:TEMP 'knowvault-operator-artifact.json'
try {
  docker cp "${container}:/usr/share/knowvault/operator-artifact.json" $artifactPath | Out-Null
  $artifact = Get-Content $artifactPath -Raw | ConvertFrom-Json
  $artifact | Select-Object platform,artifact_identity,binary,migrations | ConvertTo-Json -Depth 4
} finally {
  docker rm $container | Out-Null
}
```

## Smoke acceptance

Check the image contract and exercise the offline command surface:

```text
docker image inspect knowvault-operator:0.1.0 \
  --format '{{.Config.User}} {{json .Config.Entrypoint}} {{.Config.WorkingDir}}'
docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges knowvault-operator:0.1.0 help
```

The first command must report `0:0`,
`["/knowvault-operator"]`, and `/`. The second command must exit successfully
without network access. Export the image rootfs and verify that
`knowvault-operator`, every `db/migrations/000*.sql`, and
`usr/share/knowvault/operator-artifact.json` are present, with no shell,
system CA bundle, package manager, or customer secret.

For `secrets generate`, keep `--cap-drop ALL` and add only `--cap-add CHOWN`;
mount the root-owned input and output parents explicitly. A release smoke must
run that command and then `secrets verify` against the generated mount, proving
the artifact can create the exact root:`65532` boundary it publishes.

Database subcommands intentionally receive only the administrator-approved
PostgreSQL endpoint and protected password/secret files at invocation time.
They never download code, migrations, models, or certificates; the image does
not ship customer trust material.
