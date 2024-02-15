# Changelog

## Unreleased

### Breaking changes

The `VectorsOfTrust` property on `OneLoginOptions` has been renamed to `VectorOfTrust`.


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
