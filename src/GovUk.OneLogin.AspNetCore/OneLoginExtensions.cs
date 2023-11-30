using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace GovUk.OneLogin.AspNetCore;

/// <summary>
/// Extension methods to configure authentication via GOV.UK One Login.
/// </summary>
public static partial class OneLoginExtensions
{
    /// <summary>
    /// Adds One Login authentication to <see cref="AuthenticationBuilder"/> using the default scheme.
    /// The default scheme is specified by <see cref="OneLoginDefaults.AuthenticationScheme"/>.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddOneLogin(this AuthenticationBuilder builder) =>
        builder.AddOneLogin(OneLoginDefaults.AuthenticationScheme, _ => { });

    /// <summary>
    /// Adds One Login authentication to <see cref="AuthenticationBuilder"/> using the default scheme.
    /// The default scheme is specified by <see cref="OneLoginDefaults.AuthenticationScheme"/>.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="OneLoginOptions"/>.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddOneLogin(this AuthenticationBuilder builder, Action<OneLoginOptions> configureOptions) =>
        builder.AddOneLogin(OneLoginDefaults.AuthenticationScheme, configureOptions);

    /// <summary>
    /// Adds One Login authentication to <see cref="AuthenticationBuilder"/> using the specified scheme.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="OneLoginOptions"/>.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddOneLogin(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        Action<OneLoginOptions> configureOptions) =>
        builder.AddOneLogin(authenticationScheme, OneLoginDefaults.DisplayName, configureOptions);

    /// <summary>
    /// Adds One Login authentication to <see cref="AuthenticationBuilder"/> using the specified scheme.
    /// </summary>
    /// <param name="builder">The <see cref="AuthenticationBuilder"/>.</param>
    /// <param name="authenticationScheme">The authentication scheme.</param>
    /// <param name="displayName">A display name for the authentication handler.</param>
    /// <param name="configureOptions">A delegate to configure <see cref="OneLoginOptions"/>.</param>
    /// <returns>A reference to <paramref name="builder"/> after the operation has completed.</returns>
    public static AuthenticationBuilder AddOneLogin(
        this AuthenticationBuilder builder,
        string authenticationScheme,
        string? displayName,
        Action<OneLoginOptions>? configureOptions)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentNullException.ThrowIfNull(authenticationScheme);

        if (configureOptions is not null)
        {
            builder.Services.Configure<OneLoginOptions>(authenticationScheme, configureOptions);
        }

        builder.Services.AddOptions<OneLoginOptions>(authenticationScheme).Validate(o =>
        {
            o.Validate();
            return true;
        });

        // Don't use AddOpenIdConnect(); it adds an IConfigureOptions registration that we don't want
        // (the OpenIdConnectConfigureOptions type that configures options from IConfiguration).

        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIdConnectOptions>, ConfigureOpenIdConnectForOneLogin>());
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<OpenIdConnectOptions>, OpenIdConnectPostConfigureOptions>());
        return builder.AddRemoteScheme<OpenIdConnectOptions, OpenIdConnectHandler>(authenticationScheme, displayName, _ => { });
    }
}
