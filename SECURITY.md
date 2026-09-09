# Security Policy

## Supported versions

Security fixes are applied to the latest `master` and the most recent tagged release.

## Reporting a vulnerability

Report vulnerabilities using [GitHub's private vulnerability reporting form](https://github.com/Kunde21/lanyard/security/advisories/new).
Reports are shared privately with the repository maintainers. Do not open public
issues for suspected vulnerabilities. Include a description, reproduction steps,
and affected versions; expect an acknowledgement within a few business days.

## Hardening notes for consumers

- The default state store binds correlations to the initiating browser via a
  secure cookie; deployments behind TLS-terminating proxies must forward the
  scheme so `Secure` cookies work.
- Library HTTP calls use the caller's `http.Client` (with a default client
  when none is set). Production deployments should pass `WithHTTPClient`
  with explicit timeouts.
- Tokens, credentials, and flow secrets never appear in OpenTelemetry
  telemetry or logs emitted by the library.
