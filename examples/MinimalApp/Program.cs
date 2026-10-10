using System.Text;
using System.Text.Json;
using Yukat.UpdateVerify;

if (args.Length != 4)
{
    Console.Error.WriteLine("Usage: MinimalApp <fresh-manifest> <pre-provisioned-public-key> <package> <exact-trusted-host>");
    return 2;
}
try
{
    static async Task<byte[]> ReadBounded(string filename, int limit)
    {
        await using var file = File.OpenRead(filename);
        var bytes = new byte[limit + 1];
        var count = 0;
        while (count < bytes.Length)
        {
            var read = await file.ReadAsync(bytes.AsMemory(count));
            if (read == 0) break;
            count += read;
        }
        if (count > limit) throw new InvalidDataException("Input is too large.");
        return bytes[..count];
    }
    // A real app provisions this key and protected monotonic state separately.
    // This small example performs a first check (counter floor zero); it never installs files.
    var bytes = await ReadBounded(args[0], UpdateVerifier.MaximumManifestBytes);
    var key = Encoding.ASCII.GetString(await ReadBounded(args[1], 16384));
    var manifest = UpdateVerifier.VerifyFreshManifest(bytes, key, [args[3]], new FreshnessPolicy(DateTimeOffset.UtcNow));
    await using var package = File.OpenRead(args[2]);
    await UpdateVerifier.VerifyPackageAsync(manifest, package);
    Console.WriteLine($"Checked package {manifest.Version}; metadata counter {manifest.MetadataVersion}; expiry {manifest.ExpiresAtUtc:O}");
    return 0;
}
catch (Exception error) when (error is InvalidDataException or IOException or ArgumentException or JsonException or System.Security.Cryptography.CryptographicException)
{
    Console.Error.WriteLine($"Rejected: {error.Message}");
    return 1;
}
