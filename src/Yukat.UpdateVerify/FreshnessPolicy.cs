namespace Yukat.UpdateVerify;

/// <summary>Provisioned by the application; never copied from the untrusted manifest.</summary>
public sealed record FreshnessPolicy(
    DateTimeOffset NowUtc,
    long MinimumMetadataVersion = 0,
    string? TrustedMetadataSha256 = null,
    DateTimeOffset? LastTrustedUtc = null)
{
    public TimeSpan MaximumLifetime { get; init; } = TimeSpan.FromDays(7);
    public TimeSpan AllowedClockSkew { get; init; } = TimeSpan.FromMinutes(5);
}
