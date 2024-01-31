using System.Diagnostics.CodeAnalysis;
using System.Runtime.CompilerServices;
using System.Text.Json.Nodes;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;

namespace GovUk.OneLogin.AspNetCore;

/// <summary>
/// Configuration options for authentication using GOV.UK One Login.
/// </summary>
public class OneLoginOptions
{
    private string? _claimsRequest;

    /// <summary>
    /// Initializes a new <see cref="OneLoginOptions"/>.
    /// </summary>
    public OneLoginOptions()
    {
        ClientAssertionJwtExpiry = TimeSpan.FromMinutes(5);  // One Login docs recommend 5 minutes
        VectorsOfTrust = @"[""Cl.Cm""]";

        Claims = new HashSet<string>();

        Scope = new HashSet<string>()
        {
            "openid",
            "email"
        };
    }

    /// <inheritdoc cref="OpenIdConnectOptions.MetadataAddress"/>
    [DisallowNull]
    public string? MetadataAddress { get; set; }

    /// <inheritdoc cref="OpenIdConnectOptions.ClientId"/>
    [DisallowNull]
    public string? ClientId { get; set; }

    /// <summary>
    /// Gets or sets the signing credentials of JWT assertions for authenticating the client to the token endpoint.
    /// </summary>
    [DisallowNull]
    public SigningCredentials? ClientAuthenticationCredentials { get; set; }

    /// <summary>
    /// Gets or sets the <c>aud</c> claim of JWT assertions for authenticating the client to the token endpoint.
    /// </summary>
    [DisallowNull]
    public string? ClientAssertionJwtAudience { get; set; }

    /// <summary>
    /// Gets or sets the expiration time of JWT assertions for authenticating the client to the token endpoint.
    /// </summary>
    public TimeSpan ClientAssertionJwtExpiry { get; set; }

    /// <inheritdoc cref="OpenIdConnectOptions.Scope"/>
    public ICollection<string> Scope { get; }

    /// <summary>
    /// Gets or sets the 'ui_locales'.
    /// </summary>
    public string? UiLocales { get; set; }

    /// <summary>
    /// Gets or sets the 'vtr'.
    /// </summary>
    [DisallowNull]
    public string? VectorsOfTrust { get; set; }

    /// <summary>
    /// Gets the list of claims to request.
    /// </summary>
    public ICollection<string> Claims { get; }

    /// <summary>
    /// Gets or sets the expected issuer of the core identity claim.
    /// </summary>
    public string? CoreIdentityClaimIssuer { get; set; }

    /// <summary>
    /// Gets or sets the expected signing key of the core identity claim.
    /// </summary>
    public SecurityKey? CoreIdentityClaimIssuerSigningKey { get; set; }

    /// <inheritdoc cref="RemoteAuthenticationOptions.SignInScheme"/>
    [DisallowNull]
    public string? SignInScheme { get; set; }

    /// <inheritdoc cref="RemoteAuthenticationOptions.CallbackPath"/>
    public PathString CallbackPath { get; set; }

    /// <inheritdoc cref="OpenIdConnectOptions.SignedOutCallbackPath"/>
    public PathString SignedOutCallbackPath { get; set; }

    internal bool IncludesCoreIdentityClaim => Claims.Contains(OneLoginClaimTypes.CoreIdentity);

    internal void Validate()
    {
        ValidateOptionNotNull(MetadataAddress);
        ValidateOptionNotNull(ClientId);
        ValidateOptionNotNull(ClientAuthenticationCredentials);
        ValidateOptionNotNull(ClientAssertionJwtAudience);
        ValidateOptionNotNull(VectorsOfTrust);
        ValidateOptionNotNull(SignInScheme);

        if (IncludesCoreIdentityClaim)
        {
            ValidateOptionNotNull(CoreIdentityClaimIssuer);
            ValidateOptionNotNull(CoreIdentityClaimIssuerSigningKey);
        }

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

    internal Task OnRedirectToIdentityProvider(RedirectContext context)
    {
        ValidateOptionNotNull(VectorsOfTrust);

        context.ProtocolMessage.Parameters.Add("vtr", VectorsOfTrust);

        if (Claims.Count > 0)
        {
            context.ProtocolMessage.Parameters.Add("claims", GetClaimsRequest());
        }

        if (UiLocales is not null)
        {
            context.ProtocolMessage.Parameters.Add("ui_locales", UiLocales);
        }

        return Task.CompletedTask;
    }

    private string CreateClientAssertionJwt()
    {
        // https://docs.sign-in.service.gov.uk/integrate-with-integration-environment/integrate-with-code-flow/#create-a-jwt

        ValidateOptionNotNull(ClientAssertionJwtAudience);
        ValidateOptionNotNull(ClientAuthenticationCredentials);

        var handler = new JsonWebTokenHandler();

        var jwtId = Guid.NewGuid().ToString("N");

        var tokenDescriptor = new SecurityTokenDescriptor()
        {
            Claims = new Dictionary<string, object>()
            {
                { "aud", ClientAssertionJwtAudience },
                { "iss", ClientId! },
                { "sub", ClientId! },
                { "exp", DateTimeOffset.UtcNow.Add(ClientAssertionJwtExpiry).ToUnixTimeSeconds() },
                { "jti", jwtId },
                { "iat", DateTimeOffset.UtcNow.ToUnixTimeSeconds() }
            },
            SigningCredentials = ClientAuthenticationCredentials
        };

        return handler.CreateToken(tokenDescriptor);
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
}
