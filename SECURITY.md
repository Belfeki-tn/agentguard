# Security Policy

AgentGuard is pre-release. Its stdio proxy enforces tool policies only for calls
routed through it. Approval-required calls wait for an explicit local decision,
and the proxy records metadata-only SQLite audit events. Approval access trusts
the proxy's OS user account: same-UID processes can approve or alter state.
See [APPROVAL_WORKFLOW.md](docs/APPROVAL_WORKFLOW.md) for this security boundary.

## Reporting
Do not open public issues for suspected vulnerabilities. Use GitHub's private vulnerability reporting feature if enabled for the repository. If unavailable, contact the maintainer through a privately published security contact channel (to be added before public launch).

## Scope and limitations
The proxy only governs calls routed through it. It cannot control direct tool access, a compromised host, or bypasses outside its execution boundary. Keep tool credentials least-privileged. See [MCP_PROXY.md](docs/MCP_PROXY.md) for cancellation, uncertain outcomes, and trusted upstream limitations.
