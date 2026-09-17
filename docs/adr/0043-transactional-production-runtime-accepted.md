# ADR-0043: Transactional production runtime

Status: accepted.

The production process is assembled by one opaque `composition.Runtime`. Its
constructor receives an already validated configuration snapshot and acquires
the complete capability graph before a network listener can exist:

```text
mounted trust roots
  -> mounted purpose-scoped secrets
  -> production database, audit and repositories
  -> exact current OIDC provider preflight
  -> identity/session digestors and OIDC transport codec
  -> hardened OIDC client and authenticated HTTP handlers
  -> image-owned UI
  -> configured HTTP runner
```

Every successful acquisition immediately registers a close operation. Startup
failure executes all registered operations in reverse order and continues after
an individual cleanup error. Successful construction transfers that exact stack
to Runtime. The listener is not opened by the constructor; only the one-shot
`Runtime.Run` capability may call `Runner.ListenAndServe`.

Runtime has the shared copy-safe lifecycle `READY -> RUNNING -> CLOSING ->
CLOSED`, with the direct `READY -> CLOSING -> CLOSED` path. Concurrent Run calls
fail closed. Close before Run performs cleanup without opening a listener. Close
during Run cancels its child context, waits for the runner to return and only
then closes UI, OIDC idle connections, transport codec, session digestor,
identity digestor, database and mounted-secret provider. Repeated and concurrent
Close calls wait for and return the same content-free result.

Runtime does not expose its runner, handlers, secrets, database, key capabilities
or Close authority to request handlers. Temporary key byte copies are cleared
immediately after their purpose-specific crypto owner is created. Startup does
not perform OIDC discovery, JWKS retrieval or token exchange. Trust-root and
secret rotation take effect only after a process restart and a new complete
preflight.

The future executable entry point is intentionally thin: it may load the fixed
composition configuration, establish signal cancellation, build Runtime and run
it. It must use `os.Exit(run())`, with all cleanup defers inside `run`, and may
not import lower-level database, trust, secret, OIDC, UI or listener packages.

No third-party dependency is introduced.
