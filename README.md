# YuKat Update Verify

A small .NET 8 library and command-line tool for verifying RSA-PSS signed update metadata and the integrity of a local update package. No third-party runtime packages.

Version 0.1.0. Licensed under [MIT](LICENSE). This tool has not been independently audited or integrated into production YuKat.

## What it checks

- A caller-provisioned RSA public key (at least 2048 bits), SHA-256 and RSA-PSS.
- Exact allowed HTTPS DNS hosts, port 443, no credentials or fragments.
- A bounded JSON manifest with exactly five fields; no duplicate or unknown fields.
- Signed package length and SHA-256, streamed without loading the package into memory.
- An optional trusted version floor, rejecting equal or older numeric versions.

It does **not** download, install or execute packages. It does not infer trust from a key supplied in the manifest. It does not replace Authenticode, TUF, malware scanning, or secure key custody.

## Build and test

Requires .NET 8 SDK. Run from the repository root:

```sh
dotnet build src/Yukat.UpdateVerify.Cli -c Release
dotnet run --project tests/Yukat.UpdateVerify.Tests -c Release
```

The dependency-free test executable exits nonzero on a failed assertion. It is run with `dotnet run`, not `dotnet test`. A Windows/Linux GitHub Actions workflow is prepared; it has not run until publication.

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
