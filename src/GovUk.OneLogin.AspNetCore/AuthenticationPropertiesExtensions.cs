using System.Text.Json;
using Microsoft.AspNetCore.Authentication;

namespace GovUk.OneLogin.AspNetCore;

/// <summary>
/// Extension methods for <see cref="AuthenticationProperties"/>.
/// </summary>
public static class AuthenticationPropertiesExtensions
{
    private const string VectorsOfTrustKey = "GovUk.OneLogin.AspNetCore.VectorsOfTrust";

    /// <summary>
    /// Gets the vectors of trust to use when authenticating using GOV.UK One Login.
    /// </summary>
    /// <param name="authenticationProperties">The <see cref="AuthenticationProperties"/>.</param>
    /// <returns>The vector of trust.</returns>
    /// <exception cref="InvalidOperationException"> if the vector of trust has not been set.</exception>
    public static IReadOnlyCollection<string> GetVectorsOfTrust(this AuthenticationProperties authenticationProperties)
    {
        ArgumentNullException.ThrowIfNull(authenticationProperties);

        if (!TryGetVectorsOfTrust(authenticationProperties, out var value))
        {
            throw new InvalidOperationException("Vectors of trust have not been set.");
        }

        return value;
    }

    /// <summary>
    /// Sets the vectors of trust to use when authenticating using GOV.UK One Login.
    /// </summary>
    /// <param name="authenticationProperties">The <see cref="AuthenticationProperties"/>.</param>
    /// <param name="value">The vectors of trust.</param>
    public static void SetVectorsOfTrust(this AuthenticationProperties authenticationProperties, IEnumerable<string>? value)
    {
        ArgumentNullException.ThrowIfNull(authenticationProperties);

        if (value is null)
        {
            authenticationProperties.Items.Remove(VectorsOfTrustKey);
        }
        else
        {
            var stringValue = JsonSerializer.Serialize<string[]>(value.ToArray());
            authenticationProperties.SetString(VectorsOfTrustKey, stringValue);
        }
    }

    /// <summary>
    /// Gets the vectors of trust to use when authenticating using GOV.UK One Login.
    /// </summary>
    /// <param name="authenticationProperties">The <see cref="AuthenticationProperties"/>.</param>
    /// <param name="value">The vectors of trust.</param>
    /// <returns><see langword="true"/> if the value was successfully retrieved.</returns>
    public static bool TryGetVectorsOfTrust(this AuthenticationProperties authenticationProperties, out IReadOnlyCollection<string> value)
    {
        ArgumentNullException.ThrowIfNull(authenticationProperties);

        if (authenticationProperties.Items.TryGetValue(VectorsOfTrustKey, out var stringValue) && stringValue is not null)
        {
            value = JsonSerializer.Deserialize<string[]>(stringValue)!;
            return true;
        }
        else
        {
            value = Array.Empty<string>();
            return false;
        }
    }
}
