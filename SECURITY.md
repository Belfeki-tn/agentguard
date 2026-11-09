# Security policy

Developed and maintained by **Belfeki.tn**.

AgentGuard is an early implementation. No production security assurance or
supported stable release is claimed. Security fixes should target the current
maintained development version until a version-support policy is published.

## Report vulnerabilities privately

Do not put vulnerability details, credentials, raw protocol traces, approval
previews, or unredacted audit data in public issues or pull requests. If the
repository offers **Security → Report a vulnerability**, use that private route.
Its availability and monitoring must be verified by the maintainer; this document
does not claim that repository setting is enabled.

If that route is unavailable, request a private reporting channel from the
maintainer without disclosing exploit details publicly. A verified fallback
contact has not been published in this repository. Establishing a monitored
private reporting route is a **public-release blocker** in the release checklist.
No unverified email address or response-time promise is provided.

A private report should include affected version/commit, OS/Python/MCP versions,
expected security boundary, minimal reproduction with synthetic data, impact,
and any proposed fix. Coordinate disclosure with the maintainer.

## Security boundary

- Only tool calls actually routed through the stdio proxy are governed. Remove
  direct upstream connections from the MCP host. This is not an OS sandbox.
- Upstream commands are trusted programs, running with the gateway account's
  permissions. They may act during startup/discovery or any allowed call.
- Policy evaluates exact configured server/tool identities, not argument safety,
  tool output trustworthiness, or upstream binary provenance.
- Local approval authorization trusts the effective OS user. Same-UID processes
  can approve requests, inspect memory, or alter local state. Protect untrusted
  workloads with OS isolation; cross-account delegation is not implemented.
- Approval is one attempt for an exact live invocation. Cancellation cannot roll
  back side effects already submitted. Unknown outcomes need investigation before
  manual retries; the proxy never retries automatically.
- Audit is metadata-only, local, unencrypted, and not tamper-proof. Live previews
  intentionally reveal exact arguments to the authorized operator; protect their
  terminal output, swap, core dumps, and backups.

Invalid policy, unsafe/unavailable storage, approval failure, expiration, and
missing authorization fail closed. Doctor and simulation never execute tools;
passing doctor is not a claim of end-to-end compatibility or safety. Diagnostics
omit command arguments, policy contents, and raw exception details. Do not weaken
permissions or turn on payload logging to work around sanitized errors.

## Current scope and testing

Full gateway CI targets Linux and macOS with Python 3.11–3.14 and POSIX ownership,
`O_NOFOLLOW`, SQLite FULL durability, and FIFOs. Windows proxy/approval support,
HTTP gateway transport, cloud services, dashboards, and multiple upstreams are
not implemented. Configured CI coverage must be distinguished from locally
executed verification in [validation reports](docs/MILESTONE_4_VALIDATION.md).

See [proxy scope](docs/MCP_PROXY.md), [approval trust boundaries](docs/APPROVAL_WORKFLOW.md),
[audit failures](docs/AUDIT_LOGGING.md), and [release checklist](docs/RELEASE_CHECKLIST.md).
