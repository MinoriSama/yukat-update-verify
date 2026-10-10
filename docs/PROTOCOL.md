# Signed metadata protocol, version 1

UTF-8 JSON object, exactly these case-sensitive fields:

```json
{
  "version": "1.2.3",
  "url": "https://updates.example.org/package.bin",
  "sha256": "<64 hexadecimal characters>",
  "size": 12345,
  "signature": "<base64 RSA-PSS signature>"
}
```

The above is a schema illustration, not a valid signed fixture. Generate a working synthetic fixture using the test executable.

Create the signed bytes as UTF-8 of these four strings joined by exactly one LF (`0x0a`), with **no trailing LF**:

1. Original numeric `version` string.
2. Original `url` string, without URI normalization.
3. SHA-256 hexadecimal string converted to lowercase.
4. Positive byte length as an invariant decimal integer.

Sign using RSA-PSS with SHA-256 (the .NET `RSASignaturePadding.Pss` convention, salt length equal to SHA-256 digest length). Serialize the signature as base64. JSON field order and whitespace do not participate in the signature. Duplicate/unknown fields are rejected before verification.

The verification key and the exact hostname allowlist come from the application, independently of the downloaded metadata. Key rotation and signed metadata expiration are outside version 1. Set and persist a trusted version floor to reject rollback; authenticity alone does not prove freshness. For a new signing deployment, prefer RSA 3072-bit or larger and appropriate protected key storage; private keys must never ship with clients or fixtures.

## Explicit V2 freshness mode

V2 adds `issuedAtUtc`, `expiresAtUtc`, `metadataVersion`; duplicate/unknown fields remain forbidden. The complete signed representation is:

```text
YUKAT-UPDATE-V2
version
original URL
lowercase SHA256
invariant signed package size
issuedAtUtc (yyyy-MM-ddTHH:mm:ssZ)
expiresAtUtc (yyyy-MM-ddTHH:mm:ssZ)
positive monotonic metadataVersion
```

No final newline. All time/counter fields are authenticated. V2 and V1 are separate APIs; V1 input is never accepted by the freshness API. A trusted local application provides time, metadata counter floor and the digest of previously accepted metadata. Equal-counter retry requires exact equality with that trusted digest. Expired, future-dated, overlong-lifetime, conflicting-replay and clock-rollback metadata is rejected. Policy bounds: lifetime at most 7 days, future clock tolerance at most 5 minutes.

State persistence, trustworthy clock provision, root rotation and threshold roles are application responsibilities. This format is not TUF-compatible.
