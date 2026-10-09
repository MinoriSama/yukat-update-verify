# Security boundaries

This component is not independently audited. It verifies authenticity of a small manifest and integrity of the bytes read from a caller-supplied stream. It does not certify that a package is safe to execute.

The trusted key must be provisioned independently; loading a public key from the same untrusted source as the manifest defeats authentication. An attacker holding the signing private key can authorize arbitrary packages. Rotation, revocation, expiry, multi-party signing, secure version-floor persistence and resistance to full application rollback are not implemented. Adopt a fuller update framework where these properties are required.

The exact host policy constrains a signed descriptor only: this library performs no network requests. A downloader must enforce redirect policy, TLS and transport limits itself. DNS resolution/IP policy and SSRF protection are not provided.

The library bounds input acceptance; the caller must bound its own manifest download/allocation. The CLI bounds its manifest file read. Package verification is streaming and stops upon excess bytes. Caller cancellation is supported. Timeouts and trust-key file ownership belong to the caller.

Verification applies to the open stream's bytes. Prevent replacement or modification between verification and installation; passing a path later to an installer is not sufficient protection by itself. No installer is launched by this tool. The console success message reports verification at that moment only.

No production private key or customer record belongs in an issue or report. Report suspected vulnerabilities privately to [pierrotet@outlook.com](mailto:pierrotet@outlook.com). Include the affected version, reproduction steps and expected versus actual behavior; omit credentials and personal data. Never put credentials or an undisclosed exploit in a public issue.
