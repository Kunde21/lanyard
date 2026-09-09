# Changelog

## v1.0.0-rc1

First release candidate for Lanyard 1.0. This is a prerelease, not the final
stable release.

- OAuth 2.0 and OpenID Connect relying-party flows, client credentials, refresh
  rotation, introspection, and dynamic registration.
- FAPI profile enforcement with PAR, signed requests/responses, DPoP and mTLS.
- Hardened browser-bound state stores, credential-bearing endpoint/redirect
  handling, JOSE validation, and successful token-response validation.
- Complete callback token persistence, opaque credential preservation, consumer
  redirect-policy support, and typed service error causes.
- Clarified refresh coordination, durable session storage, and private security
  reporting.

### Validation and limitations

The eighth RC review found no new blockers in its bounded consumer-integration
scope. Tests with race detection, vet, build, formatting, reachable-vulnerability
scanning and CI passed at the reviewed code snapshot. Five conformance presets
were recorded passing at `0f46722` (70 plans, zero failures); see
[conformance results](conformance/README.md) for artifacts and coverage limits.

The previously interrupted independent negative-path security review remains
incomplete. These results are not a security certification or a claim that every
provider/configuration is supported. See the
[eighth review](thoughts/reviews/stable-rc-readiness-8d38c3b.md) for scope.

Consumers should test provider interoperability and deployment-specific session
storage, refresh coordination, deadlines, and sender-constrained API requests
before adopting this prerelease. Report security issues through the private
channel in [SECURITY.md](SECURITY.md).
