using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.AspNetCore.Authentication.OAuth.Claims;
using Microsoft.IdentityModel.Tokens;

namespace GovUk.OneLogin.AspNetCore;

internal class ProcessCoreIdentityJwtClaimAction : ClaimAction
{
    public new const string ClaimType = "https://vocab.account.gov.uk/v1/coreIdentityJWT";

    private readonly JwtSecurityTokenHandler _tokenHandler;
    private readonly TokenValidationParameters _tokenValidationParameters;

    public ProcessCoreIdentityJwtClaimAction(OneLoginOptions oneLoginOptions) :
        base(ClaimType, valueType: JsonClaimValueTypes.Json)
    {
        OneLoginOptions.ValidateOptionNotNull(oneLoginOptions.CoreIdentityClaimIssuer);
        OneLoginOptions.ValidateOptionNotNull(oneLoginOptions.CoreIdentityClaimIssuerSigningKey);

        _tokenHandler = new JwtSecurityTokenHandler
        {
            MapInboundClaims = false
        };

        _tokenValidationParameters = new TokenValidationParameters()
        {
            ValidIssuer = oneLoginOptions.CoreIdentityClaimIssuer,
            ValidateAudience = false,
            IssuerSigningKey = oneLoginOptions.CoreIdentityClaimIssuerSigningKey,
            NameClaimType = "sub"
        };
    }

    public override void Run(JsonElement userData, ClaimsIdentity identity, string issuer)
    {
        // The core identity claim may not be present, even if it was requested;
        // 'If the https://vocab.account.gov.uk/v1/coreIdentityJWT property is not present, then GOV.UK One Login was not able to prove your user’s identity.'
        // https://docs.sign-in.service.gov.uk/integrate-with-integration-environment/process-identity-information/#understand-your-user-s-core-identity-claim

        if (!userData.TryGetProperty(ClaimType, out var identityJwtElement))
        {
            return;
        }

        var token = identityJwtElement.GetString();

        var coreIdentityPrincipal = _tokenHandler.ValidateToken(token, _tokenValidationParameters, out _);

        if (coreIdentityPrincipal.FindFirstValue("sub") != identity.FindFirst("sub")?.Value)
        {
            throw new SecurityTokenException("The 'sub' claim in the core identity JWT does not match the 'sub' claim from the ID token.");
        }

        identity.AddClaim(new Claim(ClaimType, token!, valueType: "JSON"));

        var vc = coreIdentityPrincipal.FindFirstValue("vc");
        if (vc is not null)
        {
            identity.AddClaim(new Claim("vc", vc, valueType: "JSON"));
        }
    }
}
