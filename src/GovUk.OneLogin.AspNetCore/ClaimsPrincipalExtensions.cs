using System.Security.Claims;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;

namespace GovUk.OneLogin.AspNetCore;

#pragma warning disable CS1591 // Missing XML comment for publicly visible type or member
public static class ClaimsPrincipalExtensions
{
    public static CoreIdentityName GetCoreIdentityName(this ClaimsPrincipal principal)
    {
        var names = GetCoreIdentityNames(principal);

        return names.SingleOrDefault(name => name.ValidUntil is null) ??
            names.Where(name => name.ValidFrom.HasValue).OrderByDescending(name => name.ValidFrom!.Value).First();
    }

    public static CoreIdentityName[] GetCoreIdentityNames(this ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var vcJson = principal.FindFirstValue("vc") ??
            throw new InvalidOperationException("Principal does not contain a vc claim.");

        JsonObject credentialSubject = JsonNode.Parse(vcJson)?.AsObject()["credentialSubject"]?.AsObject() ??
            throw GetInvalidJsonException();

        if (!credentialSubject.TryGetPropertyValue("name", out var nameArray))
        {
            throw GetInvalidJsonException();
        }

        return nameArray.Deserialize<CoreIdentityName[]>()!;

        static Exception GetInvalidJsonException() => new InvalidOperationException("vc claim contains invalid JSON.");
    }

    public static CoreIdentityBirthDate GetCoreIdentityBirthDate(this ClaimsPrincipal principal)
    {
        var birthDates = GetCoreIdentityBirthDates(principal);

        return birthDates.First();
    }

    public static CoreIdentityBirthDate[] GetCoreIdentityBirthDates(this ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);

        var vcJson = principal.FindFirstValue("vc") ??
            throw new InvalidOperationException("Principal does not contain a vc claim.");

        JsonObject credentialSubject = JsonNode.Parse(vcJson)?.AsObject()["credentialSubject"]?.AsObject() ??
            throw GetInvalidJsonException();

        if (!credentialSubject.TryGetPropertyValue("birthDate", out var birthDateArray))
        {
            throw GetInvalidJsonException();
        }

        return birthDateArray.Deserialize<CoreIdentityBirthDate[]>()!;

        static Exception GetInvalidJsonException() => new InvalidOperationException("vc claim contains invalid JSON.");
    }
}

public class CoreIdentityName
{
    [JsonConstructor]
    public CoreIdentityName(DateOnly? validFrom, DateOnly? validUntil, CoreIdentityNamePart[] nameParts)
    {
        ArgumentNullException.ThrowIfNull(nameParts);

        ValidFrom = validFrom;
        ValidUntil = validUntil;
        NameParts = nameParts;
    }

    [JsonPropertyName("validFrom")]
    public DateOnly? ValidFrom { get; }

    [JsonPropertyName("validUntil")]
    public DateOnly? ValidUntil { get; }

    [JsonPropertyName("nameParts")]
    public CoreIdentityNamePart[] NameParts { get; }

    public string FullName => string.Join(" ", NameParts.Select(part => part.Value));

    /// <inheritdoc/>
    public override string ToString() => FullName;
}

public class CoreIdentityNamePart
{
    [JsonConstructor]
    public CoreIdentityNamePart(string value, string type)
    {
        ArgumentNullException.ThrowIfNull(value);
        ArgumentNullException.ThrowIfNull(type);

        Value = value;
        Type = type;
    }

    [JsonPropertyName("value")]
    public string Value { get; }

    [JsonPropertyName("type")]
    public string Type { get; }
}

public class CoreIdentityBirthDate
{
    [JsonConstructor]
    public CoreIdentityBirthDate(DateOnly value)
    {
        Value = value;
    }

    [JsonPropertyName("value")]
    public DateOnly Value { get; }

    /// <inheritdoc/>
    public override string ToString() => Value.ToString("yyyy-MM-dd");
}
#pragma warning restore CS1591 // Missing XML comment for publicly visible type or member
