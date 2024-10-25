using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace GovUk.OneLogin.AspNetCore;

/// <summary>
/// Configuration options for authentication using GOV.UK One Login.
/// </summary>
public class OneLoginOptions
{
    private string? _claimsRequest;
    private ICollection<string> _vectorsOfTrust;
    private CoreIdentityHelper? _coreIdentityHelper;

    /// <summary>
    /// Initializes a new <see cref="OneLoginOptions"/>.
    /// </summary>
    public OneLoginOptions()
    {
        OpenIdConnectOptions = new OpenIdConnectOptions()
        {
            // RedirectPost renders a form that's automatically submitted via JavaScript;
            // to save us having to GDS-ify that for users who don't have JavaScript, use RedirectGet instead.
            AuthenticationMethod = OpenIdConnectRedirectBehavior.RedirectGet,

            ResponseType = OpenIdConnectResponseType.Code,
            ResponseMode = OpenIdConnectResponseMode.Query,
            UsePkce = false,
            GetClaimsFromUserInfoEndpoint = true,
            UseTokenLifetime = false,

            // We'll save the ID token ourselves - we need it for sign out
            SaveTokens = false,

            MapInboundClaims = false,
            DisableTelemetry = true
        };
        OpenIdConnectOptions.ProtocolValidator.RequireNonce = true;
        OpenIdConnectOptions.TokenValidationParameters.NameClaimType = "sub";
        OpenIdConnectOptions.TokenValidationParameters.AuthenticationType = "GOV.UK One Login";
        OpenIdConnectOptions.Events = Events = new DelegateEventsWrapper(this);

        ClientAssertionJwtExpiry = TimeSpan.FromMinutes(5);  // One Login docs recommend 5 minutes
        _vectorsOfTrust = new List<string>() { "Cl.Cm" };

        Claims = new List<string>();

        Scope.Clear();
        Scope.Add("openid");
        Scope.Add("email");

        UseJwtSecuredAuthorizationRequest = true;
    }

    /// <summary>
    /// The name of the One Login environment.
    /// </summary>
    /// <remarks>
    /// Reference <see cref="OneLoginEnvironments"/> for the options.
    /// </remarks>
    [DisallowNull]
    public string? Environment { get; set; }

    /// <inheritdoc cref="OpenIdConnectOptions.ClientId"/>
    [DisallowNull]
    public string? ClientId
    {
        get => OpenIdConnectOptions.ClientId;
        set => OpenIdConnectOptions.ClientId = value;
    }

    /// <summary>
    /// Gets or sets the signing credentials of JWT assertions for authenticating the client to the token endpoint.
    /// </summary>
    [DisallowNull]
    public SigningCredentials? ClientAuthenticationCredentials { get; set; }

    /// <summary>
    /// Gets or sets the expiration time of JWT assertions for authenticating the client to the token endpoint.
    /// </summary>
    public TimeSpan ClientAssertionJwtExpiry { get; set; }

    /// <inheritdoc cref="OpenIdConnectOptions.Scope"/>
    public ICollection<string> Scope => OpenIdConnectOptions.Scope;

    /// <summary>
    /// Gets or sets the 'ui_locales'.
    /// </summary>
    public string? UiLocales { get; set; }

    /// <summary>
    /// Gets or sets the vectors of trust.
    /// </summary>
    public ICollection<string> VectorsOfTrust
    {
        get => _vectorsOfTrust;
        set
        {
            ArgumentNullException.ThrowIfNull(value);
            _vectorsOfTrust = value;
        }
    }

    /// <summary>
    /// Gets the list of claims to request.
    /// </summary>
    public ICollection<string> Claims { get; }

    /// <inheritdoc cref="RemoteAuthenticationOptions.SignInScheme"/>
    [DisallowNull]
    public string? SignInScheme
    {
        get => OpenIdConnectOptions.SignInScheme;
        set => OpenIdConnectOptions.SignInScheme = value;
    }

    /// <inheritdoc cref="RemoteAuthenticationOptions.CallbackPath"/>
    public PathString CallbackPath
    {
        get => OpenIdConnectOptions.CallbackPath;
        set => OpenIdConnectOptions.CallbackPath = value;
    }

    /// <inheritdoc cref="OpenIdConnectOptions.SignedOutCallbackPath"/>
    public PathString SignedOutCallbackPath
    {
        get => OpenIdConnectOptions.SignedOutCallbackPath;
        set => OpenIdConnectOptions.SignedOutCallbackPath = value;
    }

    /// <inheritdoc cref="OpenIdConnectOptions.NonceCookie"/>
    public CookieBuilder NonceCookie
    {
        get => OpenIdConnectOptions.NonceCookie;
        set => OpenIdConnectOptions.NonceCookie = value;
    }

    /// <inheritdoc cref="RemoteAuthenticationOptions.CorrelationCookie"/>
    public CookieBuilder CorrelationCookie
    {
        get => OpenIdConnectOptions.CorrelationCookie;
        set => OpenIdConnectOptions.CorrelationCookie = value;
    }

    /// <inheritdoc cref="OpenIdConnectOptions.Events"/>
    public OpenIdConnectEvents Events { get; }

    /// <summary>
    /// Defines whether the authorization parameters will be passed as a JWT.
    /// This property is set to <see langword="true"/> by default.
    /// </summary>
    public bool UseJwtSecuredAuthorizationRequest { get; set; }

    internal OpenIdConnectOptions OpenIdConnectOptions { get; private set; }

    internal bool IncludesCoreIdentityClaim => Claims.Contains(OneLoginClaimTypes.CoreIdentity);

    internal CoreIdentityHelper CoreIdentityHelper => _coreIdentityHelper ?? throw new InvalidOperationException("DidDocumentHelper has not been created.");

    internal void Validate()
    {
        ValidateOptionNotNull(Environment);
        ValidateOptionNotNull(ClientId);
        ValidateOptionNotNull(ClientAuthenticationCredentials);
        ValidateOptionNotNull(SignInScheme);

        if (CallbackPath == null || !CallbackPath.HasValue)
        {
            ThrowMissingOptionException(nameof(CallbackPath));
        }

        if (SignedOutCallbackPath == null || !SignedOutCallbackPath.HasValue)
        {
            ThrowMissingOptionException(nameof(SignedOutCallbackPath));
        }
    }

    internal Task OnAuthorizationCodeReceived(AuthorizationCodeReceivedContext context)
    {
        // private_key_jwt authentication
        // https://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication

        var jwt = CreateClientAssertionJwt();

        context.TokenEndpointRequest!.RemoveParameter("client_secret");
        context.TokenEndpointRequest.SetParameter("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
        context.TokenEndpointRequest.SetParameter("client_assertion", jwt);

        return Task.CompletedTask;
    }

    internal async Task OnRedirectToIdentityProvider(RedirectContext context)
    {
        var vectorsOfTrust = (context.Properties.TryGetVectorsOfTrust(out var value) ? (IEnumerable<string>)value : VectorsOfTrust) ??
            throw new InvalidOperationException(
                $"VectorsOfTrust has not been set. " +
                $"Either specify it on {nameof(OneLoginOptions)} or by calling {nameof(AuthenticationPropertiesExtensions.SetVectorsOfTrust)} on {nameof(AuthenticationProperties)}.");

        var vtr = JsonSerializer.Serialize(vectorsOfTrust);
        context.ProtocolMessage.Parameters.Add("vtr", vtr);

        if (Claims.Count > 0)
        {
            context.ProtocolMessage.Parameters.Add("claims", GetClaimsRequest());
        }

        if (UiLocales is not null)
        {
            context.ProtocolMessage.Parameters.Add("ui_locales", UiLocales);
        }

        if (UseJwtSecuredAuthorizationRequest)
        {
            var configuration = await OpenIdConnectOptions.ConfigurationManager!.GetConfigurationAsync(CancellationToken.None);

            context.ProtocolMessage = new JwtSecuredAuthorizationRequestMessage(
                context.ProtocolMessage,
                createJwt: claims =>
                {
                    claims.Add("aud", configuration.AuthorizationEndpoint);
                    return CreateJwt(claims, handler => handler.SetDefaultTimesOnTokenCreation = false);
                });
        }
    }

    internal async Task OnTokenResponseReceived(TokenResponseReceivedContext context)
    {
        if (context.TokenEndpointResponse.IdToken is string idToken)
        {
            context.Properties?.StoreTokens(new[]
            {
                new AuthenticationToken()
                {
                    Name = OpenIdConnectParameterNames.IdToken,
                    Value = idToken
                }
            });
        }

        _coreIdentityHelper ??= ActivatorUtilities.CreateInstance<CoreIdentityHelper>(context.HttpContext.RequestServices, this);
        await _coreIdentityHelper.EnsureDidDocument();
    }

    private string CreateJwt(IDictionary<string, object> claims, Action<JsonWebTokenHandler>? configureHandler = null)
    {
        var handler = new JsonWebTokenHandler();
        configureHandler?.Invoke(handler);

        var tokenDescriptor = new SecurityTokenDescriptor()
        {
            Claims = claims,
            SigningCredentials = ClientAuthenticationCredentials
        };

        return handler.CreateToken(tokenDescriptor);
    }

    private string CreateClientAssertionJwt()
    {
        // https://docs.sign-in.service.gov.uk/integrate-with-integration-environment/integrate-with-code-flow/#create-a-jwt

        ValidateOptionNotNull(ClientAuthenticationCredentials);
        ValidateOptionNotNull(Environment);

        var jwtId = Guid.NewGuid().ToString("N");
        var audience = OneLoginEnvironments.GetClientAssertionJwtAudience(Environment!);

        return CreateJwt(new Dictionary<string, object>()
        {
            { "aud", audience },
            { "iss", ClientId! },
            { "sub", ClientId! },
            { "exp", DateTimeOffset.UtcNow.Add(ClientAssertionJwtExpiry).ToUnixTimeSeconds() },
            { "jti", jwtId },
            { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() }
        });
    }

    private string GetClaimsRequest()
    {
        if (_claimsRequest is not null)
        {
            return _claimsRequest;
        }

        // https://openid.net/specs/openid-connect-core-1_0.html#ClaimsParameter
        // https://docs.sign-in.service.gov.uk/integrate-with-integration-environment/integrate-with-code-flow/#create-a-url-encoded-json-object-for-lt-claims-request-gt

        var userinfo = new JsonObject();

        foreach (var claim in Claims)
        {
            userinfo.Add(claim, JsonValue.Create((string?)null));
        }

        var root = new JsonObject
        {
            { "userinfo", userinfo }
        };

        return _claimsRequest = root.ToString();
    }

    internal static void ValidateOptionNotNull([NotNull] object? option, [CallerArgumentExpression("option")] string? paramName = null)
    {
        if (option is null)
        {
            ThrowMissingOptionException(paramName!);
        }
    }

    [DoesNotReturn]
    private static void ThrowMissingOptionException(string optionName) =>
        throw new ArgumentException($"The '{optionName}' option must be provided.", optionName);

    private sealed class DelegateEventsWrapper : OpenIdConnectEvents
    {
        private readonly OneLoginOptions _options;

        public DelegateEventsWrapper(OneLoginOptions options)
        {
            _options = options;
        }

        public override Task AccessDenied(AccessDeniedContext context)
        {
            return base.AccessDenied(context);
        }

        public override Task AuthenticationFailed(AuthenticationFailedContext context)
        {
            return base.AuthenticationFailed(context);
        }

        public async override Task AuthorizationCodeReceived(AuthorizationCodeReceivedContext context)
        {
            await _options.OnAuthorizationCodeReceived(context);
            await base.AuthorizationCodeReceived(context);
        }

        public override Task MessageReceived(MessageReceivedContext context)
        {
            return base.MessageReceived(context);
        }

        public async override Task RedirectToIdentityProvider(RedirectContext context)
        {
            await _options.OnRedirectToIdentityProvider(context);
            await base.RedirectToIdentityProvider(context);
        }

        public override Task RedirectToIdentityProviderForSignOut(RedirectContext context)
        {
            return base.RedirectToIdentityProviderForSignOut(context);
        }

        public override Task RemoteFailure(RemoteFailureContext context)
        {
            return base.RemoteFailure(context);
        }

        public override Task RemoteSignOut(RemoteSignOutContext context)
        {
            return base.RemoteSignOut(context);
        }

        public override Task SignedOutCallbackRedirect(RemoteSignOutContext context)
        {
            return base.SignedOutCallbackRedirect(context);
        }

        public override Task TicketReceived(TicketReceivedContext context)
        {
            return base.TicketReceived(context);
        }

        public async override Task TokenResponseReceived(TokenResponseReceivedContext context)
        {
            await _options.OnTokenResponseReceived(context);
            await base.TokenResponseReceived(context);
        }

        public override Task TokenValidated(TokenValidatedContext context)
        {
            return base.TokenValidated(context);
        }

        public override Task UserInformationReceived(UserInformationReceivedContext context)
        {
            return base.UserInformationReceived(context);
        }
    }
}
