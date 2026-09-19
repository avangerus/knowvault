<p align="center">
  <img src="docs/assets/marketing/knowvault-hero.svg" alt="KnowVault — Company knowledge. With evidence. Your data, models and infrastructure." width="100%">
</p>

<p align="center">
  Company knowledge through a web interface, MCP and REST API.<br>
  Ask in your AI chat. Open the evidence in KnowVault. Trace the source.
</p>

<p align="center">
  <a href="#example-questions-and-answers">See examples</a> ·
  <a href="docs/GETTING_STARTED.md">Start a pilot</a> ·
  <a href="docs/MCP_ACCESS_CODE.md">Connect your agent</a> ·
  <a href="#connectors">Connectors</a> ·
  <a href="docs/PILOT-STATUS.md">Release status</a> ·
  <a href="LICENSE">Apache 2.0</a>
</p>

## Example questions and answers

Illustrative answers using fictional company data, not benchmark results. In your AI client, the model writes the answer using KnowVault's MCP tools; the web interface also offers preliminary model answers.

### Find a rule in company documents

**You:** “Production is down. Who do I call, and how quickly should they respond?”

**Answer:** “Contact the platform on-call engineer. For a P1 incident, the response target is 15 minutes. If nobody acknowledges it within that time, escalate to the incident manager. **[1]**”

<details>
<summary>Inspect example evidence [1]</summary>

**Incident response policy · P1 escalation · saved version 3**

> P1: Production unavailable. Primary contact: platform on-call engineer. Acknowledgement target: 15 minutes. Escalate to the incident manager if unacknowledged after 15 minutes.

In a real answer, the citation opens a protected KnowVault page with the retained passage, source location, saved version and provenance.

</details>

### Read a business record from SQL

**You:** “What's the amount and due date for invoice INV-0001? Has it been paid?”

**Answer:** “Invoice INV-0001 is for **USD 1,250.50**, due **October 1, 2026**. The saved record has no payment date; that alone does not prove it is still unpaid now. **[2]**”

<details>
<summary>Inspect example evidence [2]</summary>

**Prepared PostgreSQL view · invoice INV-0001 · saved entity snapshot**

| Field | Retained value |
| --- | --- |
| `invoice_id` | `INV-0001` |
| `amount` | `1250.50` |
| `currency` | `USD` |
| `due_date` | `2026-10-01` |
| `paid_at` | `null` |

The evidence address identifies the saved version. Source modification and observation timestamps help you judge freshness; this is not a live query of the billing system.

</details>

### Run an approved live database check

**You:** “Check contract status.”

**Agent action:** The MCP client matches an administrator-approved phrase, calls
`knowvault_query_run` with the versioned preset id and receives the current rows
plus an execution receipt. The call contains no SQL.

**Example answer:** “The live contract-status check returned 18 active contracts
and 2 awaiting approval at 09:42 UTC. This is a live observation, receipt
`gqat_…`; it is not a retained document citation.”

The preset is bound to a reviewed attempt, SQL hash and exposed-schema revision.
KnowVault repeats the query only through the dedicated read-only database role
with timeout, cost, row and byte limits, and records the attempt in the audit
journal. [How governed presets work](docs/GOVERNED-SQL-PRESETS.md).

### Recognize when the evidence is missing

**You:** “Did the customer approve the revised delivery date?”

**Example answer when the accessible sources do not establish approval:** “I found the proposed date in the project plan, but no customer approval in the records I could read. I cannot confirm acceptance.”

A useful answer distinguishes a documented fact from a proposal, a missing value or missing evidence. Links let you inspect that distinction yourself.

## Evidence. Audit. Protection. Local control.

KnowVault connects employees, AI agents and applications to permitted company knowledge. Its connector roadmap spans files, Git, email, messaging, wikis, business systems, databases, event streams, audio and images.

| Three ways in | What you can do |
| --- | --- |
| **[Web interface](docs/GETTING_STARTED.md)** | Search, ask a question, open evidence, manage sources and inspect access. |
| **[MCP](docs/MCP_ACCESS_CODE.md)** | Give your existing AI chat or coding agent tools to search, read, cite and follow available relations. |
| **[REST API](api/openapi.yaml)** | Integrate search, source reads and evidence relations into your own application or workflow. |

| What matters | What KnowVault provides |
| --- | --- |
| **Evidence you can open** | Exact passages, saved source versions, timestamps and fragment hashes. Follow a citation and inspect the underlying document or SQL record. |
| **Access you can audit** | Data reads and administrative actions attributed to users or service identities, with a searchable audit journal. |
| **Protected company data** | SSO through Keycloak/OIDC, workspace permissions, revocable agent credentials and authorization checks when evidence is read. |
| **Cloud-free operation** | Run ingestion, storage, search, identity and model inference on your infrastructure, using local models and a local AI client. |

## One knowledge layer. Many sources. Three ways to use it.

<img src="docs/assets/marketing/knowvault-flow.svg" alt="Company sources connect to KnowVault, which serves the web interface, MCP agents and REST API applications. The pilot supports documents and prepared PostgreSQL views; the roadmap spans code, mail, messaging, wikis, business systems, streams and media." width="100%">

**Edge / on-premises:** configure local embeddings, a local LLM and a local client to keep the knowledge workflow inside your network. Built-in cloud model profiles are optional and controlled per workspace. Air-gapped installation packaging and hardware sizing remain subject to [pilot qualification](docs/PILOT-STATUS.md).

## From an AI answer to the evidence

**Click a citation in your chat and enter KnowVault.** Your agent includes the returned evidence-page link in its answer. The page shows the retained passage, context within that fragment, source location, saved version and provenance. Share the link with a colleague; their own permissions determine what they can open.

<img src="docs/assets/marketing/knowvault-evidence-journey.svg" alt="Illustrative journey: ask in an MCP-compatible chat, follow a citation to a protected KnowVault evidence page, then explore related materials through MCP or API. Related-document navigation inside the evidence page is planned." width="100%">

**Follow the connections:** MCP and REST API expose the available stored relations between addressed materials. Bringing those related-document links into the evidence page is the next UI step; it is not shown there today.

## Connectors

**A broad connector roadmap, not just a document folder.** Bring documents, business records and team knowledge into the same evidence workflow.

| Availability | Sources |
| --- | --- |
| **Available in the pilot** | Server folders: Markdown, plain text, supported DOCX and text-based PDF. Prepared PostgreSQL views: versioned entity snapshots with typed values and provenance. |
| **Implemented; outside pilot acceptance** | GitHub/GitLab APIs, mounted Git checkouts, and read-only IMAP email with attachments. Git checkout refresh is operator-managed. |

**The roadmap: company knowledge in every form.**

- **Code, mail and conversations:** Git platforms, Exchange/Gmail, Slack, Teams, Telegram and enterprise messengers.
- **Documents and shared knowledge:** SharePoint, Google Drive, network shares, Confluence, Notion, websites and intranets.
- **Business systems:** CRM, ERP, service desks, project trackers, SQL/NoSQL databases and data warehouses.
- **Storage and integrations:** S3-compatible stores, REST/GraphQL APIs, webhooks and scheduled exports.
- **Data in motion:** Kafka, RabbitMQ, NATS, MQTT, enterprise integration buses and database change streams.
- **Audio and visual knowledge:** recordings, meeting transcripts, video, photos, screenshots, scans and OCR/VLM document extraction.

Explore the [connector and format roadmap](docs/CONNECTOR-ROADMAP.md) for platform examples and intended coverage. These are development directions; delivery order follows customer priorities. The pilot remains folders and prepared PostgreSQL views.

## Connect your agent

Connect your client to `https://<your-knowvault-host>/api/v1/mcp` using **Streamable HTTP** and `Authorization: Bearer <access-code>`. A workspace owner issues the code in **Access**; store it in your client's private configuration.

[MCP setup](docs/MCP_ACCESS_CODE.md) · [Search and read tools](docs/MCP-TOOLS.md) · [SQL snapshot contract](docs/SQL-SNAPSHOTS.md)

## Pilot status

**Operator-assisted MCP pilot.** Built-in model answers are preliminary; a valid citation does not establish answer completeness. OCR, Excel analysis, arbitrary SQL analytics and a qualified offline installation bundle are outside this release guarantee. [Measured results and limits](docs/PILOT-STATUS.md).

**Stack:** Go · PostgreSQL · OpenSearch · Keycloak · React / TypeScript.

[Documentation](docs/README.md) · [Contributing](CONTRIBUTING.md) · [Testing](docs/TESTING.md) · [Report an issue](https://github.com/avangerus/knowvault/issues/new/choose) · [Security](SECURITY.md)

Licensed under [Apache-2.0](LICENSE). Third-party components and model artifacts retain their [own licenses](architecture/licenses.yaml).
