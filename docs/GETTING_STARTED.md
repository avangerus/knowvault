# Get started with KnowVault

The current pilot is an operator-assisted installation. Once your organization
has a running instance, you can search its connected knowledge in the browser,
from an MCP client, or through an application using the REST API.
See [Pilot status](PILOT-STATUS.md) for the supported scope.

## What you need

- The HTTPS address of your organization's KnowVault instance and a user account.
- Access to at least one workspace containing connected data.
- For an external agent, an HTTP MCP client that can reach the instance and
  trust its TLS certificate.

Your organization's operator provides network access, identity configuration,
and trust material. A remotely hosted AI client must be able to reach the MCP
endpoint; a private-network deployment is not automatically reachable from a
cloud service. Do not disable TLS verification to work around this.

## Search and inspect a source

1. Sign in and choose the workspace for your task.
2. Enter a question or search phrase. Start with a concrete document, entity, or
   identifier, such as “What is the payment deadline for invoice INV-0001?”
3. Open a result to inspect the saved text, source identity, version, and time.
4. If a model answer is enabled, check its citations against those sources.

The browser supports independent questions. Search and source reading remain
available when model answers are disabled or unavailable. Available models
depend on the deployment and workspace configuration; built-in answers are
preliminary.

A citation from an MCP-compatible chat can open this same protected source
page through the returned `source_page_url`. It shows the retained fragment
and its provenance. Available relations to other materials can be read through
MCP or REST API; related-document navigation is not yet present on this page.

A source page shows the version retained by KnowVault. It does not download
the original DOCX or PDF. After an update, a retained address still identifies
its original version, subject to current permissions and retention. Check the
source status and observation time when your question requires current data.

## Live database checks

Some workspaces offer a **Live database checks** panel in the browser. It runs a
small set of administrator-approved checks against a governed read-only database
connection; you cannot type SQL or supply parameters.

1. Choose one administrator-approved check from the panel.
2. Run it and inspect the result: it is marked `LIVE_OBSERVATION` and shows the
   database and connection identity, the exact read window, a typed table, and a
   collapsed receipt.
3. Reloading the page does not repeat the check; run it again when you need a
   fresh result.

These are live values and are not a retained evidence page — no stable source
address is created for them. Continue to use search and cited sources when an
answer needs a retained, citable page.

## Connect your agent

A workspace owner creates a service access code in the workspace's **Access**
tab. Give it a recognizable name and expiry, then copy the code when it is
shown. The raw code is not displayed again.

Configure your client's HTTP MCP connection with:

```text
Endpoint: https://<your-knowvault-host>/api/v1/mcp
Header:   Authorization: Bearer <access-code>
```

Provide the agent with the workspace ID it may use. Keep the code in private
client configuration, never in a repository or prompt shared with others.
Revoking the code in KnowVault prevents subsequent authenticated calls.

[MCP access codes](MCP_ACCESS_CODE.md) includes the Claude Code configuration
and API lifecycle. The [agent guide](MCP-CLIENT-GUIDE.md) explains evidence
reading, source links, and incomplete results. The [tool reference](MCP-TOOLS.md)
documents the full protocol.

Try a request such as:

> Find invoice INV-0001 in this workspace. Read the source, report its amount
> and payment deadline, and include links to the evidence. State the source time.

Your agent chooses how to search and reason. KnowVault returns the authorized
data and provenance; a search snippet alone is not the complete source.

## Connect data

Source setup requires an operator and the appropriate organization and workspace
roles. Source access is granted through KnowVault's workspace controls; do not
assume that the original folder or database permissions are copied automatically.

### Documents

The operator mounts an approved server folder read-only for the worker and
registers its mount identity. A path on your laptop is not automatically visible
to that worker.

In the workspace's **Sources** page, add the prepared folder using its registered
alias, identity, and relative path. Complete the required confirmation, trust
verification, and activation steps. Then inspect synchronization status, object
counts, and any skipped documents.

The pilot accepts Markdown and plain text, plus supported DOCX and PDFs with a
text layer through standard extraction. Scans needing OCR and Excel analysis
are outside the pilot. A document that fails extraction must not be treated as
successfully updated merely because an older version is readable.

### PostgreSQL

Ask the DBA to expose prepared views through a dedicated read-only database role.
Each row represents one entity and follows the [SQL snapshot contract](SQL-SNAPSHOTS.md).
The operator supplies the connection credential reference, DNS reachability,
and trusted TLS configuration.

Use source discovery to inspect the available views, resolve reported contract
issues, and add the intended view. Complete source confirmation and activation,
then verify a known entity against the database. The source form does not
create network routes, database grants, or secret mounts.

## Install a new instance

The repository contains a [Compose bootstrap](../deploy/compose/README.md) and
the [deployment contract](DEPLOYMENT.md). They are useful starting points for an
operator, but a clean-clone installation reproducing the current pilot has not
yet been qualified as a turnkey release.

The existing bootstrap builds images, provisions identity and database state,
generates development TLS material, and fetches an embedding model on its first
start. It assumes host tools and permissions that must be reviewed before use.
It is not an offline installation bundle or a production security baseline.

Before adding company data, verify login, source ingestion, MCP reads, denial
outside the permitted workspace, credential revocation, and audit on the exact
installation. Use synthetic data for this initial check. Deployment work and
operator involvement remain part of the current pilot.
