# GOV.UK One Login for ASP.NET Core

This library contains extensions to ASP.NET Core's authentication system to integrate with GOV.UK One Login.

## Installation

Install the [GovUk.OneLogin.AspNetCore NuGet package](https://www.nuget.org/packages/GovUk.OneLogin.AspNetCore/)


## Configuration

```cs
using GovUk.OneLogin.AspNetCore;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication(defaultScheme: OneLoginDefaults.AuthenticationScheme)
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddOneLogin(options =>
    {
        // Configure the authentication scheme to persist user information with;
        // typically this will be 'Cookies'.
        options.SignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;

        // Configure the One Login environment.
        options.Environment = OneLoginEnvironments.Integration;

        // Configure your client information.
        // CallbackPath and SignedOutCallbackPath must align with the redirect_uris and post_logout_redirect_uris configured in One Login.
        options.ClientId = "YOUR_CLIENT_ID";
        options.CallbackPath = "/onelogin-callback";
        options.SignedOutCallbackPath = "/onelogin-logout-callback";

        // Configure the private key used for authentication.
        // See the RSA class' documentation for the various ways to do this.
        // Here we're loading a PEM-encoded private key from configuration.
        using (var rsa = RSA.Create())
        {
            rsa.ImportFromPem(builder.Configuration["OneLogin:PrivateKeyPem"]);
            options.ClientAuthenticationCredentials = new SigningCredentials(
                new RsaSecurityKey(rsa.ExportParameters(includePrivateParameters: true)), SecurityAlgorithms.RsaSha256);
        }

        // Configure vectors of trust.
        // See the One Login docs for the various options to use here.
        options.VectorsOfTrust = ["Cl"];

        // Override the cookie name prefixes (optional)
        options.CorrelationCookie.Name = "my-app-onelogin-correlation.";
        options.NonceCookie.Name = "my-app-onelogin-nonce.";
    });
```


### Identity verification

If you're using One Login for identity verification you will need some additional configuration:

```cs
.AddOneLogin(options =>
{
    options.VectorsOfTrust = ["Cl.Cm.P2"];

    // Add the additional claims to authorization requests.
    options.Claims.Add(OneLoginClaimTypes.CoreIdentity);
})
```


### Two stage authentication and ID verification

If you're using identity verification, [One Login recommend](https://docs.sign-in.service.gov.uk/integrate-with-integration-environment/authenticate-your-user/#make-a-request-for-authentication-and-identity) sending two separate requests;
one for authentication and one for identity. To do this you can override the `VectorsOfTrust` configured in `OneLoginOptions` on a per-request basis; an example is shown below.

```cs
public IActionResult SignIn()
{
    var properties = new AuthenticationProperties();
    properties.SetVectorsOfTrust(["Cl.Cm"]);  // authentication only
    //properties.SetVectorsOfTrust(["Cl.Cm.P2"]);  // identity verification
    return Challenge(properties, authenticationSchemes: OneLoginDefaults.AuthenticationScheme);
}
```



## Retrieving user information

After the user is signed in, `HttpContext.User` will be populated with a `ClaimsPrincipal` containing all the claims returned from One Login.

| Claim | Description |
| --- | --- |
| `sub` | The user's ID. |
| `email` | The user's email address. |
| `vot` | The authentication level. |
| `sid` | The session identifier. |

If identity verification was requested *and* identity verification was successful then a `https://vocab.account.gov.uk/v1/coreIdentityJWT` claim will also be present. Its value is JSON-encoded.
See the [One Login docs](https://docs.sign-in.service.gov.uk/integrate-with-integration-environment/prove-users-identity/#prove-your-user-39-s-identity) for more information on the data contained in this claim.

A set of extension methods over `ClaimsPrincipal` is provided for extracting the user's name and birth date from the core identity JWT -
`GetCoreIdentityName()`, `GetCoreIdentityNames()`, `GetCoreIdentityBirthDate()` and `GetCoreIdentityBirthDates()`.


## Integrating with a database

You may want to add enrich the `ClaimsPrincipal` with information from your own database. Or, you may want to add users to a database when they sign in for the first time. One way to achieve this is to define your own `Microsoft.AspNetCore.Authentication.IClaimsTransformation`. An example is shown below that retrieves user information from a database using Entity Framework Core.

```cs
public class AddNameFromDbClaimsTransformation : IClaimsTransformation
{
    private readonly MyDbContext _dbContext;

    public AddNameFromDbClaimsTransformation(MyDbContext dbContext)
    {
        _dbContext = dbContext;
    }

    public async Task<ClaimsPrincipal> TransformAsync(ClaimsPrincipal principal)
    {
        if (principal.HasClaim(claim => claim.Type == "Name"))
        {
            // Already have a Name claim assigned.
            return;
        }

        // Lookup user in DB using One Login user ID
        var oneLoginId = principal.FindFirstValue("sub");
        var user = await _dbContext.Users.SingleAsync(user => user.OneLoginId == oneLoginId);

        // Create a new ClaimsIdentity, add claims and append to the existing principal
        var additionalIdentity = new ClaimsIdentity();
        additionalIdentity.AddClaim(new Claim("Name", user.Name));
        principal.AddIdentity(additionalIdentity);

        return principal;
    }
}

// In your Program.cs
builder.Services.AddTransient<AddNameFromDbClaimsTransformation, IClaimsTransformation>();
```
