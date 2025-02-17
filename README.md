# oauth-servlets

OAuth-Servlets is a library of servlets and filters using the [Nimbus OAuth SDK](https://connect2id.com/products/nimbus-oauth-openid-connect-sdk) and [Caffeine](https://github.com/ben-manes/caffeine) to implement an OAuth resource server.

# Rationale

For a few years I've been copy/pasting some code to implement bearer token introspection, most of the time using `java.net.http` or [OkHttp](https://square.github.io/okhttp/) for HTTP requests to the OAuth Introspection Endpoint, [Jackson](https://github.com/FasterXML/jackson) for JSON parsing of the response, and [Caffeine](https://github.com/ben-manes/caffeine) for caching of introspection responses.

I've had that need again, though with slightly different requirements, and after making [OIDC-Servlets](https://github.com/tbroyer/oidc-servlets/) I thought I'd write a similar library for OAuth, also built on top of the Nimbus OAuth SDK.

# Requirements

The project requires a JDK in version 21 or higher.

You will need Docker Compose to run the tests locally (e.g. to contribute).

## Usage

Add a dependency on [`net.ltgt.oauth:oauth-servlets`](https://central.sonatype.com/artifact/net.ltgt.oauth/oauth-servlets).

Create a `TokenIntrospector` object and add it as a `ServletContext` attribute:

```java
var tokenIntrospector = new TokenIntrospector(/* … */);

servletContext.setAttribute(TokenIntrospector.CONTEXT_ATTRIBUTE_NAME, tokenIntrospector);
```

> [!NOTE]
> You can also use the filters' constructors if you instantiate them yourself (or through a dependency-injection framework), rather than using `ServletContext` attributes. The same is true for values passed as init parameters.

Register the `TokenFilter`, most likely to all requests, and it should match early; this filter will setup the `HttpServletRequest` for later filters and servlets to answer the `getRemoteUser()`, `getUserPrincipal()`, and `isUserInRole()` methods:

```java
// Using the ServletContext dynamic registration (e.g. from ServletContextInitializer)
servletContext.addFilter("token", TokenFilter.class)
    .addMappingForUrlPatterns(null, false, "/*");
```

The `TokenPrincipal` returned by `getUserPrincipal()` also exposes an `hasScope()` method to easily check whether the token is valid for a given scope value.

The implementation of `isUserInRole(String)` relies on the actual `TokenPrincipal`, which is derived from the Introspection response. The default implementation (`SimpleTokenPrincipal`) always returns `false` (the user has no known role). Other implementations can be used by configuring a `TokenPrincipalProvider` as a `ServletContext` attribute. Another built-in implementation reads Keycloak realm roles from the Introspection response, and can be configured by using the `KeycloakTokenPrincipal.PROVIDER` provider:

```java
servletContext.setAttribute(
    TokenPrincipalFactory.CONTEXT_ATTRIBUTE_NAME, KeycloakTokenPrincipal.PROVIDER);
```

Custom implementations can also read additional data (e.g. from a database) to expose in their custom `TokenPrincipal`. If they can't afford doing it on each request, or would just rather do it once and _cache_ it for some time, they can extend `CachedTokenPrincipalProvider` or use it to wrap any existing `TokenPrincipalProvider`.

### Authorizations

The `TokenFilter` will pass all requests down the filter chain (unless their `Authorization: Bearer` header is invalid or contains an invalid, expired or revoked token); it'll specifically chain down any request without an `Authorization` header. To enforce authorizations, add additional filters to check the `TokenPrincipal`:

* The `IsAuthenticatedFilter` for instance only checks that a `TokenPrincipal` is indeed present (i.e. the request must include an `Authorization: Bearer` header with a valid token).
* The `HasRoleFilter` checks whether the user has a given role; this requires using a custom `TokenPrincipal` (if only a `KeycloakTokenPrincipal`).
* The `HasScopeFilter` will also check whether the token has a given scope value, and will respond with an `insufficient_scope` error otherwise.

### Cache configuration

The `TokenIntrospector` and `CachedTokenPrincipalProvider` both use a Caffeine cache to coordinate concurrent requests and cache the result. Their constructors expect a `Caffeine` cache builder configured with eviction and possibly refresh durations. Those should be configured depending on the application's security needs: shorter eviction means that you detect revocations earlier but put a higher load on the Authorization Server and possibly cause some latency depending on the cache refresh policy; determining the configuration also depends on the access tokens' lifetime.

For typical tokens with a 60-minute lifetime, a good configuration could be `expireAfterAccess=10m, refreshAfterWrite=5m`, meaning that you detect revocations after at most 5 minutes, and keep the Introspection Response in the cache for 10 minutes after a token has been tentatively used (even if it's invalid or after it has expired; which prevents useless introspection requests).

Depending on the cost of providing a `TokenPrincipal`, a `CachedTokenPrincipalProvider` could use the same cache configuration as the `TokenIntrospector` or a shorter one, and/or possibly no refresh. Using a longer expiration will uselessly consume memory though.
