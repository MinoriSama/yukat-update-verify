# Verification evidence

Checked at UTC: 2026-10-09T15:15:52.1287541Z

- Build and execution: an isolated checkout on the project owner's Windows build PC.
- .NET SDK: 8.0.423. Release build: zero errors, zero warnings.
- Library/protocol tests: **41/41 passed**.
- CLI file-based checks: **5/5 passed** (valid file, version replay, usage exit code, altered bytes, oversized manifest).
- Streaming nonseekable input, cancellation, signature/key errors, malformed fields and truncation are included in the library suite.
- Initial CLI run exposed an uncaught `InvalidDataException`; the handler was corrected and the full check passed afterward.
- Source files reviewed for scope and trust boundaries; scan for private-key blocks, Telegram and GitHub token patterns found no matches. A pattern scan is not an exhaustive secret audit.
- No third-party runtime dependencies. No production YuKat key or customer data copied.
- Windows verified locally; Linux workflow is prepared but **not executed**. No GitHub-hosted run, independent security audit, production integration or publication performed.

Run `powershell -NoProfile -ExecutionPolicy Bypass -File check.ps1` on Windows to reproduce.
Local transcript and JSON receipt are in ignored `artifacts/`; they are not part of the source archive.
