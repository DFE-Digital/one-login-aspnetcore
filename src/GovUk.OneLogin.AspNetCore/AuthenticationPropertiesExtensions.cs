using System.Diagnostics.CodeAnalysis;
using Microsoft.AspNetCore.Authentication;

namespace GovUk.OneLogin.AspNetCore;

/// <summary>
/// Extension methods for <see cref="AuthenticationProperties"/>.
/// </summary>
public static class AuthenticationPropertiesExtensions
{
    private const string VectorOfTrustKey = "GovUk.OneLogin.AspNetCore.VectorOfTrust";

    /// <summary>
    /// Gets the vector of trust to use when authenticating using GOV.UK One Login.
    /// </summary>
    /// <param name="authenticationProperties">The <see cref="AuthenticationProperties"/>.</param>
    /// <returns>The vector of trust.</returns>
    /// <exception cref="InvalidOperationException"> if the vector of trust has not been set.</exception>
    public static string GetVectorOfTrust(this AuthenticationProperties authenticationProperties)
    {
        ArgumentNullException.ThrowIfNull(authenticationProperties);

        if (!TryGetVectorOfTrust(authenticationProperties, out var value))
        {
            throw new InvalidOperationException("Vector of trust has not been set.");
        }

        return value;
    }

    /// <summary>
    /// Sets the vector of trust to use when authenticating using GOV.UK One Login.
    /// </summary>
    /// <param name="authenticationProperties">The <see cref="AuthenticationProperties"/>.</param>
    /// <param name="value">The vector of trust.</param>
    public static void SetVectorOfTrust(this AuthenticationProperties authenticationProperties, string? value)
    {
        ArgumentNullException.ThrowIfNull(authenticationProperties);

        authenticationProperties.SetString(VectorOfTrustKey, value);
    }

    /// <summary>
    /// Gets the vector of trust to use when authenticating using GOV.UK One Login.
    /// </summary>
    /// <param name="authenticationProperties">The <see cref="AuthenticationProperties"/>.</param>
    /// <param name="value">The vector of trust.</param>
    /// <returns><see langword="true"/> if the value was successfully retrieved.</returns>
    public static bool TryGetVectorOfTrust(this AuthenticationProperties authenticationProperties, [NotNullWhen(true)] out string? value)
    {
        ArgumentNullException.ThrowIfNull(authenticationProperties);

        return authenticationProperties.Items.TryGetValue(VectorOfTrustKey, out value);
    }
}
