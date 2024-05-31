# Changelog

## Unreleased

Adds support for JWT-secured OAuth 2.0 authorisation request (JAR) and enables it by default.

Replaces the `string` `VectorOfTrust` property on `OneLoginOptions` with an `ICollection<string>` property `VectorOfTrusts`.

## 0.3.1

Adds `NationalInsuranceNumber` member to `OneLoginClaimTypes`.

Adds `OpenIdConnectEvents` property to `OneLoginOptions` to allow more control over the OIDC interactions with One Login.

## 0.3.0

### New features

Vector of trust can overriden on a per-request basis by calling `SetVectorOfTrust()` on the `AuthenticationProperties` passed to `Challenge`.

### Breaking changes

The `VectorsOfTrust` property on `OneLoginOptions` has been renamed to `VectorOfTrust`.

### Fixes

Fixes sign out with a `post_logout_redirect_uri` by sending the `id_token_hint`.


## 0.2.1

Fixes population of underlying `OpenIdConnectOptions`.


## 0.2.0

### Added cookie options

`NonceCookie` and `CorrelationCookie` properties have been added to `OneLoginOptions`. With this the default cookie name prefixes can be overriden e.g.
```cs
options.CorrelationCookie.Name = "my-app-onelogin-correlation.";
options.NonceCookie.Name = "my-app-nonce-cookie.";
```


## 0.1.2

Fixes the authorization request when no claims are requested.

## 0.1.1

Adds a set of extension methods for extracting information from the core identity claim.

## 0.1.0

Initial release
