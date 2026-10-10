# YuKat Update Verify

A small .NET 8 library and command-line tool for verifying RSA-PSS signed update metadata and the integrity of a local update package. No third-party runtime packages.

Version 0.2.0 candidate. Licensed under [MIT](LICENSE). This tool has not been independently audited or integrated into production YuKat.

## What it checks

- A caller-provisioned RSA public key (at least 2048 bits), SHA-256 and RSA-PSS.
- Exact allowed HTTPS DNS hosts, port 443, no credentials or fragments.
- A bounded JSON manifest with exactly five fields; no duplicate or unknown fields.
- Signed package length and SHA-256, streamed without loading the package into memory.
- An optional trusted version floor, rejecting equal or older numeric versions.
- Explicit V2 mode: signed issuance/expiry, metadata counter, conflicting replay and trusted clock rollback checks. The application owns protected state.

It does **not** download, install or execute packages. It does not infer trust from a key supplied in the manifest. It does not replace Authenticode, TUF, malware scanning, or secure key custody.

## Build and test

Requires .NET 8 SDK. Run from the repository root:

```sh
dotnet build src/Yukat.UpdateVerify.Cli -c Release
dotnet run --project tests/Yukat.UpdateVerify.Tests -c Release
```

The dependency-free test executable exits nonzero on a failed assertion. It is run with `dotnet run`, not `dotnet test`. The Windows/Linux GitHub Actions workflow verifies changes. Local candidate builds and package validation run on the Windows build PC.

## Try a synthetic signed example

```sh
dotnet run --project tests/Yukat.UpdateVerify.Tests -c Release -- --example artifacts/example
dotnet run --project src/Yukat.UpdateVerify.Cli -c Release -- artifacts/example/manifest.json artifacts/example/trusted-public.pem artifacts/example/package.bin updates.example.org 1.2.2
```

The fixture generator creates an ephemeral signing key in memory and exports only its public key. The payload is text, not an installer. This example is not a production trust source.

CLI arguments: manifest path, trusted public key path, package path, comma-separated exact allowed hosts, optional minimum **exclusive** numeric version. Exit codes: `0` verified, `1` failure, `2` wrong argument count. No wildcard host rules. Numeric versions use `System.Version`, not semantic prerelease versions; `1.2` and `1.2.0` can compare differently.

## Library integration

```csharp
using Yukat.UpdateVerify;

// Bound the manifest read before passing bytes to the library.
byte[] metadata = /* at most 32768 bytes from your transport */;
string trustedKey = /* public key provisioned with your application */;
var manifest = UpdateVerifier.VerifyManifest(
    metadata, trustedKey, new[] { "updates.example.org" },
    minimumExclusiveVersion: new Version(1, 2, 2));

await using var package = File.OpenRead("download.partial");
await UpdateVerifier.VerifyPackageAsync(manifest, package, cancellationToken);
// Only metadata and the bytes of this open stream have now been checked.
// Use your own secure installation workflow, protecting verified bytes from replacement.
```

`VerifiedManifest` means the **metadata** passed signature verification; the caller still must invoke `VerifyPackageAsync`. The stream is read from its current position to EOF and remains caller-owned. Validation failures throw; malformed JSON/key material can throw framework parsing/cryptography exceptions. Do not treat failure as a fallback to unsigned updates.

## Manifest format

See [protocol](docs/PROTOCOL.md) and [security boundaries](SECURITY.md). The signed representation is deliberately compatible with the five-field metadata construction in YuKat's Windows updater, but input parsing is stricter. Existing manifests must be evaluated before adopting this library in any production client.

## Project status

This is a reusable component derived from the verification needs of YuKat. No production keys, customer data, VPN engines, application UI, or deployment credentials are included. There are no claims of third-party adoption or downloads. Current verification evidence is in [VALIDATION.md](VALIDATION.md).

## Install the prepared packages

The 0.2.0 candidate is not yet published on NuGet.org. Use its reviewed local feed:

```sh
dotnet add package Yukat.UpdateVerify --version 0.2.0 --source ./artifacts/packages
dotnet tool install Yukat.UpdateVerify.Tool --version 0.2.0 --tool-path ./artifacts/tool --add-source ./artifacts/packages
```

The tool command is `yukat-update-verify`; pass `--fresh` before the normal arguments to require V2 signed expiry. The CLI does not persist counter state. Applications should use the library API with a caller-provisioned `FreshnessPolicy` and protected high-watermark state.

A working [minimal application](examples/MinimalApp) consumes the packed NuGet library, rather than a project reference. It performs a first fresh check and verifies package bytes without executing them. For subsequent checks, protect the last metadata counter, exact metadata SHA256 and trusted check time. Commit that state only after the corresponding package has passed verification. A rollback of that state or a compromised local clock weakens freshness protection.

V1 metadata remains intentionally compatible and has no signed expiry. `VerifyFreshManifest` rejects V1 instead of silently downgrading. V2 includes exactly eight fields and signs domain `YUKAT-UPDATE-V2`, then the V1 four-line descriptor, then issuance UTC, expiry UTC and invariant counter. Times use UTC seconds; metadata lifetime is capped at seven days. The same fresh metadata bytes can be retried for an interrupted download, but a different digest at the same trusted counter is rejected.

See the [key rotation plan](docs/KEY-ROTATION.md) and [independent review kit](docs/INDEPENDENT-REVIEW.md). No independent review or NuGet.org publication is claimed.
