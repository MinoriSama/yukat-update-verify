# Independent review kit

Status: no independent reviewer has been assigned. Automated and author-run tests are not an external audit.

Use an isolated machine with .NET 8. Do not provide private YuKat source, signing keys, customer data or installation credentials.

1. Read `SECURITY.md`, `docs/PROTOCOL.md`, `docs/KEY-ROTATION.md` and the small verifier implementation.
2. Check trust provisioning, canonical bytes and the V1/V2 separation. Attempt duplicate fields, malformed numbers, URL authority tricks, a wrong key, modified payloads and oversized streaming input.
3. Attempt signed expired/future metadata, counter rollback, conflicting equal-counter replay and clock rollback. Confirm that the application must preserve its own protected counter/digest/time after package verification.
4. Run `check.ps1`; independently alter its fixtures instead of relying solely on the supplied assertions. Confirm that no downloaded bytes are executed and no private keys are exported.
5. Install the local NuGet package into the minimal sample with the local package feed. Run the positive example and a damaged package case. Inspect both nupkg archives, their dependency declarations and licensing.
6. Record the exact commit, SDK/OS, commands, findings and remaining limits. Report vulnerabilities privately to the address in `SECURITY.md`.

Completion requires a named external reviewer and their actual report. This file is preparation, not that report.
