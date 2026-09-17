# Connector and format roadmap

**Company knowledge spans files, conversations, business systems and live data.**
KnowVault's direction is to bring that knowledge into one permission-aware
search and evidence workflow, accessible through the web interface, MCP and REST API.

This is a target coverage map. Named products illustrate intended integrations;
they are not a list of certified or currently available connectors. Delivery
order is driven by customer use cases, available APIs and operational cost.
This roadmap does not expand the [current pilot](PILOT-STATUS.md).

## Available today

| Status | Coverage |
| --- | --- |
| **Pilot** | Mounted server folders with Markdown, plain text and supported DOCX/text-based PDF; prepared PostgreSQL views represented as versioned entity snapshots. Scheduled refresh is supported. |
| **Implemented, outside pilot qualification** | GitHub/GitLab API sources, mounted Git checkouts, and read-only IMAP messages and attachments. Git checkout refresh is operator-managed. |

## Target connector families

Each row below describes future coverage or an expansion beyond today's scope.

| Family | Target platforms and interfaces | Knowledge to retrieve |
| --- | --- | --- |
| **Files and network shares** | SMB, NFS, SFTP, WebDAV, managed upload and watched folders | Documents, reports, exports and project files. |
| **Code and engineering** | GitHub, GitLab, Bitbucket, Azure DevOps, Gitea, Forgejo | Repository content, pull requests, issues, review discussions and release notes. Existing Git support does not establish all of this coverage. |
| **Mail and calendars** | IMAP extensions, Microsoft 365 / Exchange through Graph, Gmail, CalDAV, EML/MBOX imports | Messages, attachments, threads and meeting context. |
| **Messaging and collaboration** | Slack, Microsoft Teams, Telegram, Mattermost, Rocket.Chat, Matrix, Discord | Permitted channels, threads, attachments and decisions. |
| **Drives and content management** | SharePoint, OneDrive, Google Drive, Nextcloud, Box, Dropbox, Alfresco | Shared files, libraries, metadata and document revisions. |
| **Wikis and knowledge bases** | Confluence, Notion, MediaWiki, BookStack, Outline, DokuWiki | Pages, spaces, attachments and linked internal knowledge. |
| **Websites and intranets** | HTML crawling, sitemaps, RSS/Atom, authenticated portals and rendered pages | Published guidance, internal portals, product documentation and updates. |
| **Projects, support and IT operations** | Jira, YouTrack, Linear, Redmine, Zendesk, Freshdesk, ServiceNow | Tasks, incidents, resolutions, change requests and runbooks. |
| **CRM and ERP** | Salesforce, Dynamics 365, HubSpot, SAP, Odoo, 1C, Bitrix24 | Customer records, orders, invoices, inventory and business documents. |
| **Databases and analytics stores** | MySQL/MariaDB, SQL Server, Oracle, SQLite, ClickHouse, MongoDB, Elasticsearch/OpenSearch; expanded PostgreSQL coverage | Selected records, prepared datasets and their provenance. Each source needs its own extraction and access contract. |
| **Warehouses and lakehouses** | Snowflake, BigQuery, Redshift, Databricks and governed dataset exports | Approved analytical datasets, definitions and snapshots. |
| **Object and archive storage** | S3-compatible storage, MinIO, Azure Blob, Google Cloud Storage | Objects, metadata, retained versions and archival collections. |
| **Events and data buses** | Kafka, Redpanda, RabbitMQ, NATS, MQTT, enterprise service buses | Selected event streams with source identity, offsets and event timestamps. |
| **Change feeds and application APIs** | CDC, Debezium, transactional outboxes, REST, GraphQL, OData, webhooks and scheduled exports | Record changes and application-specific knowledge without a bespoke connector for every system. |

Cloud-backed sources are optional. A fully local deployment uses locally
reachable sources, identity services, embeddings, models and agent clients.
Connecting a cloud source does not make that source local.

## Beyond text: target processing capabilities

Connectors acquire data; extraction makes its contents searchable. Audio,
images and scans require dedicated processing in addition to a connector.
These capabilities are **planned and outside the current pilot guarantee**.

| Input | Intended processing | Intended evidence address |
| --- | --- | --- |
| **Audio and voice messages** | Speech recognition, speaker labels and searchable transcripts | Recording version, speaker where known, and time interval. |
| **Meetings and video** | Transcripts, slide/frame extraction and meeting attachments | Timestamped transcript passage or frame in the original recording. |
| **Photos and screenshots** | OCR/VLM extraction of visible text and relevant visual content | Original image version and the supporting region. |
| **Scans and image-based PDFs** | OCR/VLM with layout and extraction-quality metadata | Document version, page and region. |
| **Tables and spreadsheets** | Structured extraction from CSV, XLSX and ODS | Workbook/snapshot version, sheet and cell range. |
| **Presentations and diagrams** | Text, slide structure and visual extraction from PPTX/ODP and diagrams | Slide or diagram version and the relevant region. |
| **Archives and compound documents** | Controlled unpacking and attachment relationships | Original container, member path and extracted version. |

The goal is evidence that retains its source location, rather than a transcript
or caption detached from the material it describes. Generated interpretations
must remain distinguishable from original source content.

## What every integration must preserve

- **Provenance:** original identity, source address, version and observation time.
- **Controlled access:** explicit workspace/source permissions and authorized reads.
  Upstream permission inheritance must be designed and verified per integration.
- **Audit:** attribution of data access to the employee or service identity.
- **Lifecycle:** observable refresh, failures, updates, deletion and return behavior.
- **Evidence:** a retained, addressable passage or record that the recipient can inspect.

To prioritize a connector, describe the business question, the source system,
the data and permissions required, and the evidence an employee should receive.
[Propose an integration](https://github.com/avangerus/knowvault/issues/new?template=feature_request.yml).
