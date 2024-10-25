using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace GovUk.OneLogin.AspNetCore;

internal sealed class CoreIdentityHelper : IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly OneLoginOptions _options;
    private readonly ILogger<CoreIdentityHelper> _logger;
    private readonly JwtSecurityTokenHandler _tokenHandler;
    private readonly SemaphoreSlim _lock = new SemaphoreSlim(1, 1);  // The lock that guards against multiple DID requests happening at once.
    private Did? _did;
    private DateTimeOffset? _didExpires;

    public CoreIdentityHelper(HttpClient httpClient, OneLoginOptions options, ILogger<CoreIdentityHelper> logger)
    {
        ArgumentNullException.ThrowIfNull(httpClient);
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(logger);

        _httpClient = httpClient;
        _options = options;
        _logger = logger;

        _tokenHandler = new JwtSecurityTokenHandler
        {
            MapInboundClaims = false
        };
    }

    public void Dispose() => _httpClient.Dispose();

    internal ClaimsPrincipal ValidateCoreIdentity(string coreIdentityJwt)
    {
        if (_did is null)
        {
            throw new InvalidOperationException("DID has not been fetched.");
        }

        OneLoginOptions.ValidateOptionNotNull(_options.Environment);
        var coreIdentityClaimIssuer = OneLoginEnvironments.GetCoreIdentityClaimIssuer(_options.Environment);

        var tokenValidationParameters = new TokenValidationParameters()
        {
            ValidIssuer = coreIdentityClaimIssuer,
            ValidateAudience = false,
            NameClaimType = "sub",
            IssuerSigningKeyResolver = (string token, SecurityToken securityToken, string kid, TokenValidationParameters validationParameters) =>
            {
                var controllerId = kid.Split('#')[0];
                if (controllerId != _did.Id)
                {
                    return Enumerable.Empty<SecurityKey>();
                }

                var assertionMethods = _did.JwkAssertionMethods;
                return assertionMethods.Where(am => am.Id == kid).Select(am => am.Key);
            }
        };

        var coreIdentityPrincipal = _tokenHandler.ValidateToken(coreIdentityJwt, tokenValidationParameters, out var securityKey);

        return coreIdentityPrincipal;
    }

    internal async Task EnsureDidDocument()
    {
        if (_did is null)
        {
            await LoadDid();
        }
        else if (_didExpires is DateTimeOffset expires && expires < DateTimeOffset.UtcNow)
        {
            // Docs say that a cached document should be used if refreshing the document fails
            // so we should not bubble up any exceptions here.

            try
            {
                await LoadDid();
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to refresh DID document.");
            }
        }

        Debug.Assert(_did is not null);
    }

    private async Task LoadDid()
    {
        OneLoginOptions.ValidateOptionNotNull(_options.Environment);
        var endpoint = OneLoginEnvironments.GetDidEndpoint(_options.Environment);

        await _lock.WaitAsync();
        try
        {
            var response = await _httpClient.GetAsync(endpoint);
            response.EnsureSuccessStatusCode();

            DateTimeOffset? didDocumentExpires = null;
            if (response.Headers.CacheControl?.MaxAge is TimeSpan maxAge)
            {
                didDocumentExpires = DateTimeOffset.UtcNow.Add(maxAge);
            }

            using var document = JsonSerializer.Deserialize<JsonDocument>(await response.Content.ReadAsStringAsync())!;

            if (!document.RootElement.TryGetProperty("id", out var docIdElement) || docIdElement.ValueKind != JsonValueKind.String)
            {
                throw new Exception("DID does not contain an 'id' string property.");
            }
            if (!document.RootElement.TryGetProperty("assertionMethod", out var assertionMethodsElement) || assertionMethodsElement.ValueKind != JsonValueKind.Array)
            {
                throw new Exception("DID does not contain an 'assertionMethod' array property.");
            }

            var docId = docIdElement.GetString()!;

            var assertionMethods = new List<JwkAssertionMethod>();

            foreach (var assertionMethod in assertionMethodsElement.EnumerateArray())
            {
                var type = assertionMethod.GetProperty("type").GetString();
                if (type != "JsonWebKey")
                {
                    continue;
                }

                if (assertionMethod.TryGetProperty("id", out var idElement) && idElement.ValueKind == JsonValueKind.String &&
                    assertionMethod.TryGetProperty("controller", out var controllerElement) && controllerElement.ValueKind == JsonValueKind.String &&
                    assertionMethod.TryGetProperty("publicKeyJwk", out var publicKeyJwkElement) && publicKeyJwkElement.ValueKind == JsonValueKind.Object)
                {
                    var key = JsonWebKey.Create(publicKeyJwkElement.ToString());

                    assertionMethods.Add(new JwkAssertionMethod(idElement.GetString()!, controllerElement.GetString()!, key));
                }
            }

            _did = new Did(docId, assertionMethods.ToArray());
            _didExpires = didDocumentExpires;
        }
        finally
        {
            _lock.Release();
        }
    }

    private class Did
    {
        public Did(string id, JwkAssertionMethod[] jwkAssertionMethods)
        {
            Id = id;
            JwkAssertionMethods = jwkAssertionMethods;
        }

        public string Id { get; }
        public JwkAssertionMethod[] JwkAssertionMethods { get; }
    }

    private class JwkAssertionMethod
    {
        public JwkAssertionMethod(string id, string controller, JsonWebKey key)
        {
            Id = id;
            Controller = controller;
            Key = key;
        }

        public string Id { get; }
        public string Controller { get; }
        public JsonWebKey Key { get; }
    }
}
