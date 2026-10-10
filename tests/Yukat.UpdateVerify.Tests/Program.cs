using System.Globalization;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Yukat.UpdateVerify;

using var signingKey = RSA.Create(2048);
using var wrongKey = RSA.Create(2048);
var publicKey = signingKey.ExportSubjectPublicKeyInfoPem();
var payload = Encoding.UTF8.GetBytes("Example update package. This is not an executable.\n");
var hash = Convert.ToHexString(SHA256.HashData(payload)).ToLowerInvariant();
byte[] Signed(string version = "1.2.3", string url = "https://updates.example.org/package.bin",
    string? digest = null, long? size = null)
{
    digest ??= hash;
    size ??= payload.Length;
    var canonical = string.Join('\n', version, url, digest.ToLowerInvariant(), size.Value.ToString(CultureInfo.InvariantCulture));
    var signature = Convert.ToBase64String(signingKey.SignData(Encoding.UTF8.GetBytes(canonical), HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    return JsonSerializer.SerializeToUtf8Bytes(new { version, url, sha256 = digest, size, signature });
}
var signed = Signed();
byte[] Edit(string name, JsonNode? value)
{
    var node = JsonNode.Parse(signed)!.AsObject();
    node[name] = value;
    return Encoding.UTF8.GetBytes(node.ToJsonString());
}
VerifiedManifest Verify(byte[] json, string? pem = null, Version? floor = null) =>
    UpdateVerifier.VerifyManifest(json, pem ?? publicKey, ["updates.example.org"], floor);
var checks = new List<(string Name, Func<Task> Run)>();
void Accept(string name, Func<Task> run) => checks.Add((name, run));
void Reject(string name, Func<Task> run) => checks.Add((name, async () =>
{
    try { await run(); }
    catch (Exception error) when (error is InvalidDataException or JsonException or ArgumentException or CryptographicException or OperationCanceledException) { return; }
    throw new Exception("Unexpected acceptance.");
}));
Task CheckManifest(byte[] json) { Verify(json); return Task.CompletedTask; }
Accept("valid signed package", async () => await UpdateVerifier.VerifyPackageAsync(Verify(signed), new MemoryStream(payload)));
Accept("uppercase digest canonicalization", () => CheckManifest(Signed(digest: hash.ToUpperInvariant())));
Accept("trusted host comparison ignores case", () => { UpdateVerifier.VerifyManifest(signed, publicKey, ["UPDATES.EXAMPLE.ORG"]); return Task.CompletedTask; });
Accept("newer than floor", () => { Verify(signed, floor: new Version(1, 2, 2)); return Task.CompletedTask; });
Accept("culture independent signed integer", () =>
{
    var old = CultureInfo.CurrentCulture;
    try { CultureInfo.CurrentCulture = new CultureInfo("ar-SA"); Verify(signed); }
    finally { CultureInfo.CurrentCulture = old; }
    return Task.CompletedTask;
});
Reject("wrong trusted key", () => { Verify(signed, wrongKey.ExportSubjectPublicKeyInfoPem()); return Task.CompletedTask; });
Reject("tampered version", () => CheckManifest(Edit("version", "9.0.0")));
Reject("tampered allowed URL", () => CheckManifest(Edit("url", "https://updates.example.org/other.bin")));
Reject("tampered digest", () => CheckManifest(Edit("sha256", new string('0', 64))));
Reject("tampered signed size", () => CheckManifest(Edit("size", payload.Length + 1)));
Reject("invalid signature base64", () => CheckManifest(Edit("signature", "!")));
Reject("empty signature", () => CheckManifest(Edit("signature", "")));
Reject("HTTP even with valid signature", () => CheckManifest(Signed(url: "http://updates.example.org/package.bin")));
Reject("untrusted host even with valid signature", () => CheckManifest(Signed(url: "https://evil.example.org/package.bin")));
Reject("hostname suffix trick", () => CheckManifest(Signed(url: "https://updates.example.org.evil.org/package.bin")));
Reject("credentials in URL", () => CheckManifest(Signed(url: "https://user@updates.example.org/package.bin")));
Reject("custom port", () => CheckManifest(Signed(url: "https://updates.example.org:444/package.bin")));
Reject("fragment in URL", () => CheckManifest(Signed(url: "https://updates.example.org/package.bin#x")));
Reject("newline in URL", () => CheckManifest(Signed(url: "https://updates.example.org/package\n.bin")));
Reject("newline in version", () => CheckManifest(Signed(version: "1.2\n3")));
Reject("prerelease version unsupported", () => CheckManifest(Signed(version: "1.2.3-beta")));
Reject("same version replay", () => { Verify(signed, floor: new Version(1, 2, 3)); return Task.CompletedTask; });
Reject("older version replay", () => { Verify(signed, floor: new Version(2, 0)); return Task.CompletedTask; });
Reject("oversize package declaration", () => CheckManifest(Signed(size: UpdateVerifier.DefaultMaximumPackageBytes + 1)));
Reject("negative package size", () => CheckManifest(Signed(size: -1)));
Reject("noninteger size", () => CheckManifest(Edit("size", 1.5)));
Reject("invalid SHA-256", () => CheckManifest(Edit("sha256", new string('x', 64))));
Reject("null field", () => CheckManifest(Edit("url", null)));
Reject("unknown field", () => CheckManifest(Edit("extra", "value")));
Reject("missing field", () => { var node = JsonNode.Parse(signed)!.AsObject(); node.Remove("url"); return CheckManifest(Encoding.UTF8.GetBytes(node.ToJsonString())); });
Reject("duplicate field", () => CheckManifest(Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(signed).Replace("{", "{\"version\":\"9.0.0\","))));
Reject("JSON array", () => CheckManifest("[]"u8.ToArray()));
Reject("manifest byte limit", () => CheckManifest(new byte[UpdateVerifier.MaximumManifestBytes + 1]));
Reject("empty host policy", () => { UpdateVerifier.VerifyManifest(signed, publicKey, []); return Task.CompletedTask; });
Reject("wildcard host policy", () => { UpdateVerifier.VerifyManifest(signed, publicKey, ["*.example.org"]); return Task.CompletedTask; });
Reject("weak RSA key", () => { using var weak = RSA.Create(1024); Verify(signed, weak.ExportSubjectPublicKeyInfoPem()); return Task.CompletedTask; });
Reject("damaged package same length", async () => { var damaged = payload.ToArray(); damaged[0] ^= 1; await UpdateVerifier.VerifyPackageAsync(Verify(signed), new MemoryStream(damaged)); });
Reject("truncated package", async () => await UpdateVerifier.VerifyPackageAsync(Verify(signed), new MemoryStream(payload[..^1])));
Reject("extra package bytes", async () => await UpdateVerifier.VerifyPackageAsync(Verify(signed), new MemoryStream([..payload, 0])));
Reject("cancellation", async () => { using var cancel = new CancellationTokenSource(); cancel.Cancel(); await UpdateVerifier.VerifyPackageAsync(Verify(signed), new MemoryStream(payload), cancel.Token); });
Accept("nonseekable chunked stream stays open", async () =>
{
    using var stream = new ChunkedStream(payload);
    await UpdateVerifier.VerifyPackageAsync(Verify(signed), stream);
    if (!stream.CanRead) throw new Exception("Caller stream was closed.");
});
var now = new DateTimeOffset(2026, 10, 10, 12, 0, 0, TimeSpan.Zero);
byte[] SignedV2(long counter = 1, DateTimeOffset? issued = null, DateTimeOffset? expires = null, string version = "1.2.3")
{
    var issuedAtUtc = (issued ?? now).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
    var expiresAtUtc = (expires ?? now.AddDays(1)).ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
    const string url = "https://updates.example.org/package.bin";
    var canonical = string.Join('\n', "YUKAT-UPDATE-V2", version, url, hash, payload.Length.ToString(CultureInfo.InvariantCulture), issuedAtUtc, expiresAtUtc, counter.ToString(CultureInfo.InvariantCulture));
    var signature = Convert.ToBase64String(signingKey.SignData(Encoding.UTF8.GetBytes(canonical), HashAlgorithmName.SHA256, RSASignaturePadding.Pss));
    return JsonSerializer.SerializeToUtf8Bytes(new { version, url, sha256 = hash, size = payload.Length, signature, issuedAtUtc, expiresAtUtc, metadataVersion = counter });
}
Task Fresh(byte[] bytes, FreshnessPolicy? policy = null) { UpdateVerifier.VerifyFreshManifest(bytes, publicKey, ["updates.example.org"], policy ?? new(now)); return Task.CompletedTask; }
Accept("fresh V2 metadata and package", async () => await UpdateVerifier.VerifyPackageAsync(UpdateVerifier.VerifyFreshManifest(SignedV2(), publicKey, ["updates.example.org"], new(now)), new MemoryStream(payload)));
Reject("expired signed V2", () => Fresh(SignedV2(issued: now.AddDays(-2), expires: now)));
Reject("future-dated signed V2", () => Fresh(SignedV2(issued: now.AddMinutes(6))));
Reject("excessive signed lifetime", () => Fresh(SignedV2(expires: now.AddDays(8))));
Reject("expiry before issuance", () => Fresh(SignedV2(expires: now.AddSeconds(-1))));
Reject("metadata counter rollback", () => Fresh(SignedV2(), new(now, MinimumMetadataVersion: 2)));
Reject("equal counter without trusted digest", () => Fresh(SignedV2(), new(now, MinimumMetadataVersion: 1)));
Reject("zero counter", () => Fresh(SignedV2(counter: 0)));
Reject("trusted clock rollback", () => Fresh(SignedV2(), new(now, LastTrustedUtc: now.AddMinutes(1))));
Reject("legacy verifier never silently accepts V2", () => CheckManifest(SignedV2()));
Reject("fresh verifier never silently accepts legacy", () => Fresh(signed));
Accept("identical fresh replay allowed for interrupted download", () => {
    var bytes = SignedV2(); var accepted = UpdateVerifier.VerifyFreshManifest(bytes, publicKey, ["updates.example.org"], new(now));
    return Fresh(bytes, new(now, 1, accepted.MetadataSha256, now));
});
Reject("conflicting same-counter replay", () => {
    var accepted = UpdateVerifier.VerifyFreshManifest(SignedV2(), publicKey, ["updates.example.org"], new(now));
    return Fresh(SignedV2(version: "1.2.4"), new(now, 1, accepted.MetadataSha256, now));
});
Reject("tampered expiry", () => {
    var node = JsonNode.Parse(SignedV2())!.AsObject(); node["expiresAtUtc"] = now.AddDays(2).ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
    return Fresh(Encoding.UTF8.GetBytes(node.ToJsonString()));
});
Reject("duplicate metadata counter", () => Fresh(Encoding.UTF8.GetBytes(Encoding.UTF8.GetString(SignedV2()).Replace("{", "{\"metadataVersion\":999,"))));
var failed = 0;
foreach (var (name, run) in checks)
{
    try { await run(); Console.WriteLine($"PASS {name}"); }
    catch (Exception error) { failed++; Console.Error.WriteLine($"FAIL {name}: {error.Message}"); }
}
Console.WriteLine($"{checks.Count - failed}/{checks.Count} passed");
if (failed == 0 && args is ["--example", var directory])
{
    Directory.CreateDirectory(directory);
    var generatedAt = DateTimeOffset.UtcNow;
    File.WriteAllBytes(Path.Combine(directory, "fresh-manifest.json"), SignedV2(issued: generatedAt, expires: generatedAt.AddDays(1)));
    await File.WriteAllBytesAsync(Path.Combine(directory, "manifest.json"), signed);
    await File.WriteAllTextAsync(Path.Combine(directory, "trusted-public.pem"), publicKey);
    await File.WriteAllBytesAsync(Path.Combine(directory, "package.bin"), payload);
    // Ephemeral signing key is disposed, never exported or written.
    Console.WriteLine("Synthetic example created. No private key exported.");
}
return failed == 0 ? 0 : 1;

sealed class ChunkedStream(byte[] data) : Stream
{
    private readonly MemoryStream inner = new(data);
    public override bool CanRead => inner.CanRead;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override int Read(byte[] buffer, int offset, int count) => inner.Read(buffer, offset, Math.Min(3, count));
    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default) => inner.ReadAsync(buffer[..Math.Min(3, buffer.Length)], cancellationToken);
    public override void Flush() => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    protected override void Dispose(bool disposing) { if (disposing) inner.Dispose(); base.Dispose(disposing); }
}
