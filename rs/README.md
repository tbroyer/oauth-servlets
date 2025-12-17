# oauth-rs

OAuth-RS is a library of JAX-RS container filters using the [Nimbus OAuth SDK](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk) and [Caffeine](https://github.com/ben-manes/caffeine) to help implement an OAuth resource server.
It is the JAX-RS twin of [OAuth-Servlets](../README.md), and can also be used as a companion in a servlets environment.

## Requirements

The project requires a JDK in version 21 or higher.

You will need Docker Compose to run the tests locally (e.g. to contribute).

## Usage

Add a dependency on [`net.ltgt.oauth:oauth-rs`](https://central.sonatype.com/artifact/net.ltgt.oauth/oauth-rs). You can also use the [`net.ltgt.oauth:oauth-bom`](https://central.sonatype.com/artifact/net.ltgt.oauth/oauth-bom) BOM to make sure the library uses the same version of its [`net.ltgt.oauth:oauth-common`](https://central.sonatype.com/artifact/net.ltgt.oauth/oauth-common) dependency (and possibly align the version with OAuth-Servlets when used conjointly).
You should also add a dependency on [`com.nimbusds:oauth2-oidc-sdk`](https://central.sonatype.com/artifact/com.nimbusds/oauth2-oidc-sdk) so you can keep it up-to-date independently of OAuth-RS.

Create a `TokenIntrospector` object and add it as a property to a `Configuration` (most likely at the `Application` level):

```java
class MyApplication implements Application {
  // …

  @Override
  public Map<String, Object> getProperties() {
    return Map.of(
        TokenIntrospector.CONTEXT_PARAMETER_NAME, tokenIntrospector);
  }
}
```

In a servlet environment, you can also use a `ServletContext` attribute to populate the `Configuration`:

```java
var tokenIntrospector = new TokenIntrospector(/* … */);

servletContext.setAttribute(TokenIntrospector.CONTEXT_ATTRIBUTE_NAME, tokenIntrospector);
```


> [!NOTE]
> You can also extend the filters and override their internal getters if you instantiate them yourself (or through a dependency-injection framework), rather than using `Configuration` properties.

Register the `TokenFilter`, most likely to all requests; this should happen automatically if you use automatic discovery. This filter will setup the `SecurityContext` for later filters and resources to answer the `getUserPrincipal()` and `isUserInRole()` methods.

The `TokenPrincipal` returned by `getUserPrincipal()` also exposes an `hasScope()` method to easily check whether the token is valid for a given scope value.

The implementation of `isUserInRole(String)` relies on the actual `TokenPrincipal`, which is derived from the Introspection response. The default implementation (`SimpleTokenPrincipal`) always returns `false` (the user has no known role). Other implementations can be used by configuring a `TokenPrincipalProvider` as a `Configuration` property. Another built-in implementation reads Keycloak realm roles from the Introspection response, and can be configured by using the `KeycloakTokenPrincipal.PROVIDER` provider:

```java
servletContext.setAttribute(
    TokenPrincipalFactory.CONTEXT_ATTRIBUTE_NAME, KeycloakTokenPrincipal.PROVIDER);
```

Custom implementations can also read additional data (e.g. from a database) to expose in their custom `TokenPrincipal`. If they can't afford doing it on each request, or would just rather do it once and _cache_ it for some time, they can extend `CachedTokenPrincipalProvider` or use it to wrap any existing `TokenPrincipalProvider`.

> [!NOTE]
> If you use JAX-RS in a servlets environment, you can use the `TokenFilter` from [OAuth-Servlets](../README.md) instead of the one from OAuth-RS. It will setup the `HttpServletRequest`'s `getUserPrincipal()` with the same `TokenPrincipal`, that should be mirrored by the JAX-RS `SecurityContext`'s `getUserPrincipal()` so the two libraries can work hand-in-hand.

### DPoP

To accept DPoP tokens, register a `DPoPTokenFilterHelper.Factory` as a `Configuration` property.

For now, DPoP nonces aren't used.

### Authorizations

The _token filter_ will pass all requests down the filter chain (unless their `Authorization` header is invalid or contains an invalid, expired or revoked token); it'll specifically chain down any request without an `Authorization` header. To enforce authorizations, add additional filters to check the `TokenPrincipal`:

* The `IsAuthenticatedFilter` for instance only checks that a `TokenPrincipal` is indeed present (i.e. the request must include an `Authorization` header with a valid token). Annotate your application or resources with `@IsAuthenticated` to use bind this filter to your resources.
* The `HasRoleFilter` checks whether the user has a given role; this requires using a custom `TokenPrincipal` (if only a `KeycloakTokenPrincipal`). Register the `HasRoleFeature` and annotate your resources with `@HasRole()` to bind this filter to your resources. You can also create subclasses with a name binding; make sure to register them with a priority higher than `Priorities.AUTHENTICATION` (most likely `Priorities.AUTHORIZATION`).
* The `HasScopeFilter` will also check whether the token has a given scope value, and will respond with an `insufficient_scope` error otherwise. Register the `HasScopeFeature` and annotate your resources with `@HasScope()` to bind this filter to your resources. You can also create subclasses with a name binding; make sure to register them with a priority higher than `Priorities.AUTHENTICATION` (most likely `Priorities.AUTHORIZATION`).

### Cache configuration

See the [OAuth-Servlets docs](../README.md#cache-configuration) for details on cache configuration.
