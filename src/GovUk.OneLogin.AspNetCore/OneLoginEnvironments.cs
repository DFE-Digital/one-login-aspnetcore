using System.Reflection.Metadata;

namespace GovUk.OneLogin.AspNetCore;

/// <summary>
/// Contains the set of known One Login environments.
/// </summary>
public static class OneLoginEnvironments
{
    private static IReadOnlyDictionary<string, EnvironmentInfo> _environments = new[]
    {
        new EnvironmentInfo(
            Integration,
            MetadataAddress: "https://oidc.integration.account.gov.uk/.well-known/openid-configuration",
            ClientAssertionJwtAudience: "https://oidc.integration.account.gov.uk/token",
            CoreIdentityClaimsIssuer: "https://identity.integration.account.gov.uk/",
            DidEndpoint: "https://identity.integration.account.gov.uk/.well-known/did.json"),
        new EnvironmentInfo(
            Production,
            MetadataAddress: "https://oidc.account.gov.uk/.well-known/openid-configuration",
            ClientAssertionJwtAudience: "https://oidc.account.gov.uk/token",
            CoreIdentityClaimsIssuer: "https://identity.account.gov.uk/",
            DidEndpoint: "https://identity.account.gov.uk/.well-known/did.json")
    }
    .ToDictionary(e => e.Name, e => e);

    /// <summary>
    /// The integration environment.
    /// </summary>
    public const string Integration = "Integration";

    /// <summary>
    /// The production environment.
    /// </summary>
    public const string Production = "Production";

    internal static string GetMetadataAddress(string environment)
    {
        ArgumentNullException.ThrowIfNull(environment);

        if (!_environments.TryGetValue(environment, out var info))
        {
            throw new ArgumentException($"Unknown environment: '{environment}'.", nameof(environment));
        }

        return info.MetadataAddress;
    }

    internal static string GetClientAssertionJwtAudience(string environment)
    {
        ArgumentNullException.ThrowIfNull(environment);

        return environment switch
        {
            Integration => "https://oidc.integration.account.gov.uk/token",
            Production => "https://oidc.account.gov.uk/token",
            _ => throw new ArgumentException($"Unknown environment: '{environment}'.", nameof(environment))
        };
    }

    internal static string GetCoreIdentityClaimIssuer(string environment)
    {
        ArgumentNullException.ThrowIfNull(environment);

        return environment switch
        {
            Integration => "https://identity.integration.account.gov.uk/",
            Production => "https://identity.account.gov.uk/",
            _ => throw new ArgumentException($"Unknown environment: '{environment}'.", nameof(environment))
        };
    }

    internal static string GetDidEndpoint(string environment)
    {
        ArgumentNullException.ThrowIfNull(environment);

        return environment switch
        {
            Integration => "https://identity.integration.account.gov.uk/.well-known/did.json",
            Production => "https://identity.account.gov.uk/.well-known/did.json",
            _ => throw new ArgumentException($"Unknown environment: '{environment}'.", nameof(environment))
        };
    }

    private record EnvironmentInfo(
        string Name,
        string MetadataAddress,
        string ClientAssertionJwtAudience,
        string CoreIdentityClaimsIssuer,
        string DidEndpoint);
}
