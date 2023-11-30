using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace GovUk.OneLogin.AspNetCore;

internal class ConfigureOpenIdConnectForOneLogin : IPostConfigureOptions<OpenIdConnectOptions>
{
    private readonly IOptionsMonitor<OneLoginOptions> _oneLoginOptionsAccessor;

    public ConfigureOpenIdConnectForOneLogin(IOptionsMonitor<OneLoginOptions> oneLoginOptions)
    {
        _oneLoginOptionsAccessor = oneLoginOptions;
    }

    public void PostConfigure(string? name, OpenIdConnectOptions options)
    {
        if (string.IsNullOrEmpty(name))
        {
            return;
        }

        var oneLoginOptions = _oneLoginOptionsAccessor.Get(name);
        if (oneLoginOptions is null)
        {
            return;
        }

        options.MetadataAddress = oneLoginOptions.MetadataAddress;
        options.ClientId = oneLoginOptions.ClientId;

        // RedirectPost renders a form that's automatically submitted via JavaScript;
        // to save us having to GDS-ify that for users who don't have JavaScript, use RedirectGet instead.
        options.AuthenticationMethod = OpenIdConnectRedirectBehavior.RedirectGet;

        options.SignInScheme = oneLoginOptions.SignInScheme;
        options.ResponseType = OpenIdConnectResponseType.Code;
        options.ResponseMode = OpenIdConnectResponseMode.Query;
        options.ProtocolValidator.RequireNonce = true;
        options.UsePkce = false;
        options.GetClaimsFromUserInfoEndpoint = true;
        options.UseTokenLifetime = false;
        options.SaveTokens = false;
        options.MapInboundClaims = false;
        options.TokenValidationParameters.NameClaimType = "sub";
        options.TokenValidationParameters.AuthenticationType = "GOV.UK One Login";
        options.CallbackPath = oneLoginOptions.CallbackPath;
        options.SignedOutCallbackPath = oneLoginOptions.SignedOutCallbackPath;
        options.DisableTelemetry = true;

        options.Scope.Clear();
        foreach (var scope in oneLoginOptions.Scope)
        {
            options.Scope.Add(scope);
        }

        if (oneLoginOptions.IncludesCoreIdentityClaim)
        {
            options.ClaimActions.Add(new ProcessCoreIdentityJwtClaimAction(oneLoginOptions));
        }

        options.Events.OnRedirectToIdentityProvider = oneLoginOptions.OnRedirectToIdentityProvider;
        options.Events.OnAuthorizationCodeReceived = oneLoginOptions.OnAuthorizationCodeReceived;

        // TODO handle access_denied
        //options.Events.OnRemoteFailure = ctx =>
        //{
        //    // See https://docs.sign-in.service.gov.uk/integrate-with-integration-environment/integrate-with-code-flow/#error-handling-for-make-an-authorisation-request
        //    // ctx.Failure.Message == 'Message contains error: 'access_denied', error_description: 'Access denied by resource owner or authorization server', error_uri: 'error_uri is null'.'
        //};
    }
}
