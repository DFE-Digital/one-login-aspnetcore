using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Options;

namespace GovUk.OneLogin.AspNetCore;

/// <summary>
/// Used to configure the underlying <see cref="OpenIdConnectOptions"/>.
/// </summary>
public class OneLoginPostConfigureOptions : IPostConfigureOptions<OneLoginOptions>
{
    private readonly OpenIdConnectPostConfigureOptions _openIdConnectPostConfigureOptions;

    /// <summary>
    /// Initializes a new instance of <see cref="OneLoginPostConfigureOptions"/>.
    /// </summary>
    public OneLoginPostConfigureOptions(IDataProtectionProvider dataProtection)
    {
        ArgumentNullException.ThrowIfNull(dataProtection);
        _openIdConnectPostConfigureOptions = new OpenIdConnectPostConfigureOptions(dataProtection);
    }

    /// <inheritdoc/>
    public void PostConfigure(string? name, OneLoginOptions options)
    {
        ArgumentNullException.ThrowIfNull(name);

        options.OpenIdConnectOptions.MetadataAddress = OneLoginEnvironments.GetMetadataAddress(options.Environment!);

        if (options.IncludesCoreIdentityClaim)
        {
            options.OpenIdConnectOptions.ClaimActions.Add(new ProcessCoreIdentityJwtClaimAction(options));
        }

        _openIdConnectPostConfigureOptions.PostConfigure(name, options.OpenIdConnectOptions);
    }
}
