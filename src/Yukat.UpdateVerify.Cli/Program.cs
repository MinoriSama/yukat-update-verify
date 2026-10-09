using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Yukat.UpdateVerify;

if (args.Length < 4 || args.Length > 5)
{
    Console.Error.WriteLine("Usage: update-verify <manifest.json> <trusted-public.pem> <package> <allowed-host[,host]> [minimum-exclusive-version]");
    return 2;
}
try
{
    Version? floor = args.Length == 5 ? Version.Parse(args[4]) : null;
    var bytes = await ReadBoundedAsync(args[0], UpdateVerifier.MaximumManifestBytes);
    var keyBytes = await ReadBoundedAsync(args[1], 16_384);
    var pem = Encoding.ASCII.GetString(keyBytes);
    var manifest = UpdateVerifier.VerifyManifest(bytes, pem, args[3].Split(','), floor);
    await using var package = new FileStream(args[2], FileMode.Open, FileAccess.Read, FileShare.Read,
        64 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
    await UpdateVerifier.VerifyPackageAsync(manifest, package);
    Console.WriteLine($"Verified version {manifest.Version}; {manifest.Size} bytes; SHA-256 {manifest.Sha256}");
    return 0;
}
catch (Exception error) when (error is InvalidDataException or IOException or UnauthorizedAccessException or ArgumentException or
    FormatException or JsonException or CryptographicException)
{
    Console.Error.WriteLine($"Verification failed: {error.Message}");
    return 1;
}

static async Task<byte[]> ReadBoundedAsync(string path, int limit)
{
    await using var input = File.OpenRead(path);
    var bytes = new byte[limit + 1];
    var length = 0;
    while (length < bytes.Length)
    {
        var count = await input.ReadAsync(bytes.AsMemory(length));
        if (count == 0) break;
        length += count;
    }
    if (length > limit) throw new InvalidDataException("Input file exceeds the size limit.");
    return bytes[..length];
}
