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
- stdio client/server bridge; intercept tools/call
- Preserve upstream protocol behavior; test bypass assumptions

## Week 4: Approval and audit
- Bind approvals to exact call, identity, expiration, one-time use
- Redacted SQLite audit events

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
