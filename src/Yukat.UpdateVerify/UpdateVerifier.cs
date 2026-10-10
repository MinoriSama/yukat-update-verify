using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Yukat.UpdateVerify;

/// <summary>A descriptor whose metadata signature has been verified. This does not verify a package.</summary>
public sealed class VerifiedManifest
{
    internal VerifiedManifest(Version version, Uri url, byte[] hash, long size, long? metadataVersion = null, DateTimeOffset? expiresAtUtc = null, string? metadataSha256 = null)
    {
        Version = version;
        Url = url;
        Sha256 = Convert.ToHexString(hash).ToLowerInvariant();
        Size = size;
        MetadataVersion = metadataVersion; ExpiresAtUtc = expiresAtUtc; MetadataSha256 = metadataSha256;
    }
    public Version Version { get; }
    public Uri Url { get; }
    public string Sha256 { get; }
    public long Size { get; }
    public long? MetadataVersion { get; }
    public DateTimeOffset? ExpiresAtUtc { get; }
    public string? MetadataSha256 { get; }
}

public static class UpdateVerifier
{
    public const int MaximumManifestBytes = 32_768;
    public const long DefaultMaximumPackageBytes = 160L * 1024 * 1024;

    /// <summary>Uses a public key provisioned by the caller, never a key from the manifest.</summary>
    public static VerifiedManifest VerifyManifest(
        ReadOnlySpan<byte> json, string trustedPublicKeyPem, IEnumerable<string> allowedHosts,
        Version? minimumExclusiveVersion = null, long maximumPackageBytes = DefaultMaximumPackageBytes)
        => VerifyCore(json, trustedPublicKeyPem, allowedHosts, minimumExclusiveVersion, maximumPackageBytes, null);

    /// <summary>V2 metadata requires signed expiry, a monotonic counter and caller-owned trusted state.</summary>
    public static VerifiedManifest VerifyFreshManifest(
        ReadOnlySpan<byte> json, string trustedPublicKeyPem, IEnumerable<string> allowedHosts,
        FreshnessPolicy freshness, Version? minimumExclusiveVersion = null,
        long maximumPackageBytes = DefaultMaximumPackageBytes)
    {
        ArgumentNullException.ThrowIfNull(freshness);
        return VerifyCore(json, trustedPublicKeyPem, allowedHosts, minimumExclusiveVersion, maximumPackageBytes, freshness);
    }

    private static VerifiedManifest VerifyCore(ReadOnlySpan<byte> json, string trustedPublicKeyPem,
        IEnumerable<string> allowedHosts, Version? minimumExclusiveVersion, long maximumPackageBytes, FreshnessPolicy? freshness)
    {
        if (json.Length == 0 || json.Length > MaximumManifestBytes)
            throw new InvalidDataException("Manifest is empty or exceeds the size limit.");
        if (maximumPackageBytes <= 0)
            throw new ArgumentOutOfRangeException(nameof(maximumPackageBytes));
        ArgumentNullException.ThrowIfNull(allowedHosts);
        var hosts = allowedHosts.Select(NormalizeHost).ToHashSet(StringComparer.OrdinalIgnoreCase);
        if (hosts.Count == 0) throw new ArgumentException("At least one trusted host is required.", nameof(allowedHosts));
        using var document = JsonDocument.Parse(json.ToArray(), new JsonDocumentOptions { MaxDepth = 4 });
        var root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object) throw new InvalidDataException("Manifest must be an object.");
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var field in root.EnumerateObject())
        {
            var known = field.Name is "version" or "url" or "sha256" or "size" or "signature"
                || freshness is not null && field.Name is "issuedAtUtc" or "expiresAtUtc" or "metadataVersion";
            if (!known || !names.Add(field.Name))
                throw new InvalidDataException("Unknown or duplicate manifest field.");
        }
        if (names.Count != (freshness is null ? 5 : 8)) throw new InvalidDataException("Missing manifest field.");
        var versionText = ReadString(root, "version");
        if (versionText.Length > 64 || !versionText.All(c => char.IsAsciiDigit(c) || c == '.') ||
            !Version.TryParse(versionText, out var version))
            throw new InvalidDataException("Invalid numeric version.");
        var urlText = ReadString(root, "url");
        if (urlText.Length > 4096 || urlText.Any(c => char.IsControl(c) || char.IsWhiteSpace(c)) ||
            !Uri.TryCreate(urlText, UriKind.Absolute, out var url) || url.Scheme != Uri.UriSchemeHttps ||
            url.Port != 443 || url.UserInfo.Length != 0 || url.Fragment.Length != 0 ||
            !hosts.Contains(url.IdnHost))
            throw new InvalidDataException("Package URL does not match the HTTPS host policy.");
        var hashText = ReadString(root, "sha256");
        if (hashText.Length != 64 || !hashText.All(Uri.IsHexDigit))
            throw new InvalidDataException("Invalid SHA-256.");
        var sizeField = root.GetProperty("size");
        if (sizeField.ValueKind != JsonValueKind.Number || !sizeField.TryGetInt64(out var size) ||
            size <= 0 || size > maximumPackageBytes)
            throw new InvalidDataException("Invalid package size.");
        byte[] signature;
        try { signature = Convert.FromBase64String(ReadString(root, "signature")); }
        catch (FormatException error) { throw new InvalidDataException("Invalid base64 signature.", error); }
        var canonical = string.Join('\n', versionText, urlText, hashText.ToLowerInvariant(), size.ToString(CultureInfo.InvariantCulture));
        long? metadataVersion = null; DateTimeOffset? expiresAtUtc = null;
        var metadataDigest = Convert.ToHexString(SHA256.HashData(json)).ToLowerInvariant();
        if (freshness is not null)
        {
            var counter = root.GetProperty("metadataVersion");
            if (counter.ValueKind != JsonValueKind.Number || !counter.TryGetInt64(out var revision) || revision <= 0)
                throw new InvalidDataException("Invalid metadata counter.");
            var issuedText = ReadString(root, "issuedAtUtc");
            var expiryText = ReadString(root, "expiresAtUtc");
            if (!DateTimeOffset.TryParseExact(issuedText, "yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var issued)
                || !DateTimeOffset.TryParseExact(expiryText, "yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var expiry))
                throw new InvalidDataException("Metadata times must be UTC seconds.");
            if (freshness.MinimumMetadataVersion < 0 || freshness.MaximumLifetime <= TimeSpan.Zero
                || freshness.MaximumLifetime > TimeSpan.FromDays(7) || freshness.AllowedClockSkew < TimeSpan.Zero
                || freshness.AllowedClockSkew > TimeSpan.FromMinutes(5)) throw new ArgumentException("Invalid freshness policy.");
            if (freshness.LastTrustedUtc is { } previousTime && freshness.NowUtc < previousTime)
                throw new InvalidDataException("Clock moved behind the last trusted update check.");
            if (expiry <= issued || expiry - issued > freshness.MaximumLifetime || expiry <= freshness.NowUtc
                || issued > freshness.NowUtc + freshness.AllowedClockSkew)
                throw new InvalidDataException("Metadata is expired, future-dated or has an excessive lifetime.");
            if (revision < freshness.MinimumMetadataVersion
                || revision == freshness.MinimumMetadataVersion &&
                   (freshness.TrustedMetadataSha256 is null || !metadataDigest.Equals(freshness.TrustedMetadataSha256, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidDataException("Metadata counter rollback or conflicting replay.");
            canonical = string.Join('\n', "YUKAT-UPDATE-V2", canonical, issuedText, expiryText, revision.ToString(CultureInfo.InvariantCulture));
            metadataVersion = revision; expiresAtUtc = expiry;
        }
        using var rsa = RSA.Create();
        rsa.ImportFromPem(trustedPublicKeyPem);
        if (rsa.KeySize < 2048) throw new InvalidDataException("RSA keys must be at least 2048 bits.");
        if (!rsa.VerifyData(Encoding.UTF8.GetBytes(canonical), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
            throw new InvalidDataException("Manifest signature verification failed.");
        if (minimumExclusiveVersion is not null && version <= minimumExclusiveVersion)
            throw new InvalidDataException("Update is not newer than the trusted version floor.");
        return new VerifiedManifest(version, url, Convert.FromHexString(hashText), size, metadataVersion, expiresAtUtc, freshness is null ? null : metadataDigest);
    }

    /// <summary>Hashes from the stream's current position through EOF. Does not execute or close it.</summary>
    public static async Task VerifyPackageAsync(
        VerifiedManifest manifest, Stream package, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(manifest);
        ArgumentNullException.ThrowIfNull(package);
        using var hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        var buffer = new byte[64 * 1024];
        long received = 0;
        while (true)
        {
            var count = await package.ReadAsync(buffer.AsMemory(), cancellationToken).ConfigureAwait(false);
            if (count == 0) break;
            if (count > manifest.Size - received) throw new InvalidDataException("Package exceeds signed size.");
            received += count;
            hash.AppendData(buffer, 0, count);
        }
        if (received != manifest.Size) throw new InvalidDataException("Package is incomplete.");
        if (!CryptographicOperations.FixedTimeEquals(hash.GetHashAndReset(), Convert.FromHexString(manifest.Sha256)))
            throw new InvalidDataException("Package SHA-256 does not match signed metadata.");
    }

    private static string ReadString(JsonElement root, string name)
    {
        var field = root.GetProperty(name);
        if (field.ValueKind != JsonValueKind.String || field.GetString() is not { Length: > 0 } text)
            throw new InvalidDataException($"Invalid {name} field.");
        return text;
    }

    private static string NormalizeHost(string host)
    {
        if (string.IsNullOrWhiteSpace(host) || host.Any(c => char.IsWhiteSpace(c) || char.IsControl(c)) ||
            host.IndexOfAny(['/', ':', '@', '?', '#', '*', '\\']) >= 0 || host.EndsWith('.'))
            throw new ArgumentException("Trusted hosts must be exact DNS names without wildcards or ports.");
        var ascii = new IdnMapping().GetAscii(host);
        if (Uri.CheckHostName(ascii) != UriHostNameType.Dns)
            throw new ArgumentException("Trusted hosts must be DNS names.");
        return ascii;
    }
}
