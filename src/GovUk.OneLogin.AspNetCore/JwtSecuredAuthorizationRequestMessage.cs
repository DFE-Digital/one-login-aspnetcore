using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;

namespace GovUk.OneLogin.AspNetCore;

internal delegate string CreateJwtSecuredAuthorizationRequest(IDictionary<string, object> claims);

internal class JwtSecuredAuthorizationRequestMessage : OpenIdConnectMessage
{
    private readonly CreateJwtSecuredAuthorizationRequest _createJwt;

    public JwtSecuredAuthorizationRequestMessage(OpenIdConnectMessage message, CreateJwtSecuredAuthorizationRequest createJwt) : base(message)
    {
        ArgumentNullException.ThrowIfNull(createJwt);
        _createJwt = createJwt;
    }

    public override string CreateAuthenticationRequestUrl()
    {
        // https://openid.net/specs/openid-connect-core-1_0.html#RequestObject

        var openIdConnectMessage = Clone();
        openIdConnectMessage.RequestType = OpenIdConnectRequestType.Authentication;

        Dictionary<string, object> claims = openIdConnectMessage.Parameters
            .ToDictionary(
                kvp => kvp.Key,
                kvp =>
                {
                    if (kvp.Key is "vtr" or "claims")
                    {
                        return JsonSerializer.SerializeToElement(JsonNode.Parse(kvp.Value));
                    }
                    else
                    {
                        return (object)kvp.Value;
                    }
                });
        claims.Add("iss", ClientId);

        foreach (var key in openIdConnectMessage.Parameters.Keys)
        {
            if (key is not "response_type" and not "scope" and not "client_id")
            {
                openIdConnectMessage.RemoveParameter(key);
            }
        }

        var request = _createJwt(claims);
        openIdConnectMessage.SetParameter("request", request);

        return openIdConnectMessage.BuildRedirectUrl();
    }
}
