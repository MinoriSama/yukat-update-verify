using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace Yukat.UpdateVerify;

/// <summary>A descriptor whose metadata signature has been verified. This does not verify a package.</summary>
public sealed class VerifiedManifest
{
    internal VerifiedManifest(Version version, Uri url, byte[] hash, long size)
    {
        Version = version;
        Url = url;
        Sha256 = Convert.ToHexString(hash).ToLowerInvariant();
        Size = size;
    }
    public Version Version { get; }
    public Uri Url { get; }
    public string Sha256 { get; }
    public long Size { get; }
}

public static class UpdateVerifier
{
    public const int MaximumManifestBytes = 32_768;
    public const long DefaultMaximumPackageBytes = 160L * 1024 * 1024;

    /// <summary>Uses a public key provisioned by the caller, never a key from the manifest.</summary>
    public static VerifiedManifest VerifyManifest(
        ReadOnlySpan<byte> json, string trustedPublicKeyPem, IEnumerable<string> allowedHosts,
        Version? minimumExclusiveVersion = null, long maximumPackageBytes = DefaultMaximumPackageBytes)
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
            if (field.Name is not ("version" or "url" or "sha256" or "size" or "signature") || !names.Add(field.Name))
                throw new InvalidDataException("Unknown or duplicate manifest field.");
        }
        if (names.Count != 5) throw new InvalidDataException("Missing manifest field.");
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
        using var rsa = RSA.Create();
        rsa.ImportFromPem(trustedPublicKeyPem);
        if (rsa.KeySize < 2048) throw new InvalidDataException("RSA keys must be at least 2048 bits.");
        if (!rsa.VerifyData(Encoding.UTF8.GetBytes(canonical), signature, HashAlgorithmName.SHA256, RSASignaturePadding.Pss))
            throw new InvalidDataException("Manifest signature verification failed.");
        if (minimumExclusiveVersion is not null && version <= minimumExclusiveVersion)
            throw new InvalidDataException("Update is not newer than the trusted version floor.");
        return new VerifiedManifest(version, url, Convert.FromHexString(hashText), size);
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
