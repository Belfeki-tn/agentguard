# Roadmap — AgentGuard

Maintainer: **Belfeki.tn**

## Week 1: Validation
- Interview MCP developers, compare competing tools, finalize threat model
- Confirm project, package, and trademark naming availability

## Week 2: Policy engine
- Implemented: typed policy schema, deterministic matching, deny-by-default
- Implemented: reject unknown keys and invalid configurations
- See [policy engine architecture and semantics](POLICY_ENGINE.md)

## Week 3: MCP proxy
- Implemented: single-upstream SDK stdio adapter; intercept every tools/call
- Implemented: discovery, policy enforcement, failure/cancellation and counter-based tests
- See [MCP proxy scope and limitations](MCP_PROXY.md); broader protocol features remain planned

## Week 4: Approval and audit
- Implemented: exact-call approval binding, expiration, atomic single-use consumption
- Implemented: separate-terminal POSIX approval CLI and metadata-only SQLite audit
- See [approval workflow](APPROVAL_WORKFLOW.md) and [audit logging](AUDIT_LOGGING.md)

## Week 5: Developer experience
- CLI, dry-run policy simulator, docs, examples

## Week 6: Security hardening
- Threat modeling, property tests, malformed input tests, concurrency tests

## Week 7: Beta
- Recruit five external testers; resolve onboarding issues

## Week 8: v0.1
- Publish PyPI package and tagged GitHub release after verification

## Definition of done
A developer can route an existing MCP stdio server through AgentGuard and observe deterministic allow/deny/approve behavior, with no uncontrolled fallback when policy evaluation fails.
