# Install KnowVault

One compose stack, one bootstrap script. Requires Docker with the Compose
plugin and `openssl`/`bash` (WSL, macOS or Linux).

```bash
cd deploy/compose
cp .env.example .env        # edit the passwords and organization/owner names
./bootstrap.sh
```

`bootstrap.sh` builds the server/worker/operator images (the embedding
runtime, PostgreSQL, OpenSearch, Keycloak and the proxy are pinned upstream
images, pulled by digest), generates
local TLS material, starts PostgreSQL/OpenSearch/Keycloak/the embedding
service, runs the database migrations, creates your organization and its
first OWNER, its OWNER's login (Keycloak user *and* the database mapping
`CompleteLogin` needs to accept it — see below), its `organization_policy_
revision` row (needed the first time anyone confirms a source, ADR-0087),
and its CONNECTOR_ADMIN grant for source trust verification, then starts the
server/worker/proxy. It is safe to re-run.

Run `./bootstrap.sh --dry-run` first to see exactly what a real run would do
— it prints every step (organization/workspace/OWNER names, whether
CONNECTOR_ADMIN goes to the OWNER or to a second dual-control principal) and
validates `compose.yaml` against your `.env`, without building an image,
generating a secret, writing a database row or starting a container.

**Separation of duty (optional).** `KNOWVAULT_DUAL_CONTROL=false` (the
default) self-grants the OWNER organization-level CONNECTOR_ADMIN, so one
person can confirm a source and verify its trust alone. Set it to `true` and
fill in `KNOWVAULT_CONNECTOR_ADMIN_USERNAME`/`_DISPLAY_NAME` in `.env` to
provision a second principal — with its own Keycloak login — that holds
CONNECTOR_ADMIN instead, so the two actions (confirm, verify trust) are
never the same person (ADR-0087 §2); its generated password lands in
`secrets/connector-admin.password`.

Then:

1. Add `127.0.0.1 knowvault.local knowvault-idp.local` to your OS hosts file.
2. Open `https://knowvault.local:8480` (accept the local development certificate) and log in with the OWNER username from `.env` — its generated password is in `deploy/compose/secrets/owner.password`.
3. Add a source (folder, Git or SQL) from **Sources**.
4. Open the workspace's **Access** tab to create an MCP access code for an agent — see `docs/MCP_ACCESS_CODE.md` for the three-line Claude Code/Desktop configuration.

`docker compose -f compose.yaml --env-file .env stop` stops every container
and keeps all data/secrets; add `down --volumes` only when you intend to
discard the database and search index.

## What's in the stack

`postgres`, `opensearch`, `keycloak` (the built-in identity provider — bring
your own OIDC provider instead by editing the `server`/`worker`
`KNOWVAULT_PROVIDER_ID` and re-running `provider-register`), `embedding` (a
CPU-only multilingual model behind an mTLS-terminating proxy — see the
caveat below), `server`, `worker`, and `proxy` (the public TLS front door).

## Embedding capability — interim scope

`embedding`/`embedding-proxy` activate real semantic (not keyword-only)
retrieval and a real embedding-similarity claim verifier for generative
answers, replacing the built-in character-trigram fallback. The runtime is a
pinned upstream image (no Dockerfile of ours), and the model
(`intfloat/multilingual-e5-small`) is fetched once into the
`knowvault-embedding-cache` volume on the very first start; every later start
and every request is served from that cache, so a fully egress-denied network
still works once the volume is warm. This activation is not yet the full ADR-0080 §3 model
qualification (frozen bilingual retrieval benchmark, AIBOM, license record);
it is the same kind of explicitly-scoped interim activation ADR-0088's GEN-2
addendum used for the generative answer adapter.

### Serving the channel from a GPU model runtime

`compose.embedding-gpu.yaml` is an overlay that moves the upstream of
`embedding-proxy` off the in-compose CPU runtime and onto a model runtime on
another host. Everything above the proxy is unchanged: the same mTLS, the same
`knowvault-embedding` name, the same `https://knowvault-embedding` endpoint in
the profile. The profile schema admits no IP literal and no plaintext
endpoint, and it does not need to — the deployment's own proxy is the
endpoint, and what answers behind it is a deployment decision.

```
KNOWVAULT_EMBEDDING_UPSTREAM_IP=<model host> \
docker compose --env-file .env -f compose.yaml -f compose.embedding-gpu.yaml up -d
```

The overlay does **not** change which model the deployment claims to run. That
is `embedding-profile.json`, and it must be replaced with the identity of the
model that actually answers, because the profile hash is what every indexed
vector is stamped with. Recording that identity is an installation step, not a
committed file: a profile whose hashes do not describe the artifact behind the
proxy is worse than no profile, because it passes validation and lies. For a
llama.cpp GGUF runtime the four component hashes are, in order, the SHA-256 of
the model file, of the tokenizer the runtime loaded, of the runtime image
digest, and of the exact launch command line — on the model host:

```
sha256sum /opt/models/<vendor>/<repo>/<model>.gguf          # artifact_hash
sha256sum /opt/models/<vendor>/<repo>/tokenizer.json        # tokenizer_hash
docker image inspect --format '{{index .RepoDigests 0}}' <runtime image> | sha256sum
docker inspect --format '{{join .Args " "}}' <container> | sha256sum   # configuration_hash
```

`configuration_hash` must cover the launch parameters, not only the model:
changing `--pooling` or the context length produces different vectors for the
same text, so it produces a different profile and therefore a re-embedding.
`dimension` must be the dimension the endpoint actually returns
(`/v1/embeddings` on one short input), not the dimension the model card
claims. `profile_hash` is the SHA-256 of the canonical JSON of every other
field; the server recomputes it at startup and refuses a profile whose
declared hash does not match, so a typo fails the deployment closed instead of
poisoning a vector space.

### Turning it on later, on a workspace that already has data

A fresh install started with this compose file is semantic from the first
run: the worker records the mounted embedding profile as the workspace's
first retrieval profile revision before it indexes anything.

An installation that ran without the embedding service, or one that moves to
a different model, does **not** switch silently — the answers it already
gives were retrieved under the old profile. Switching is one command, run by
an owner of the workspace:

```
POST /api/v1/workspaces/<workspace>/search-profile:revise
```

The worker then re-reads the whole corpus under the new profile and switches
the workspace over only when it is finished; until then every question is
still answered from the profile the corpus was actually indexed under.
`GET /api/v1/workspaces/<workspace>/search-profile` shows the current
profile and whether a switch is still running. The command is safe to repeat
— once the workspace is on the mounted profile it does nothing.
