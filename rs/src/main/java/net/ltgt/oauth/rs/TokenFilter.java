package net.ltgt.oauth.rs;

import static java.util.Objects.requireNonNull;

import com.google.errorprone.annotations.ForOverride;
import com.nimbusds.oauth2.sdk.token.TokenSchemeError;
import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.Configuration;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import jakarta.ws.rs.ext.Provider;
import java.io.IOException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.List;
import net.ltgt.oauth.common.BearerTokenFilterHelper;
import net.ltgt.oauth.common.SimpleTokenPrincipal;
import net.ltgt.oauth.common.TokenFilterHelper;
import net.ltgt.oauth.common.TokenIntrospector;
import net.ltgt.oauth.common.TokenPrincipal;
import net.ltgt.oauth.common.TokenPrincipalProvider;
import org.jspecify.annotations.Nullable;

/**
 * Authenticates the request using a Bearer token and introspecting it, if provided in the request.
 *
 * <p>Initializes the security context's {@link SecurityContext#getUserPrincipal()
 * getUserPrincipal()}, and implements its {@link SecurityContext#isUserInRole isUserInRole(String)}
 * for other filters and resources down the chain. The user principal will be created by the {@link
 * TokenPrincipalProvider} present in the {@link Configuration}.
 *
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-14.html">The OAuth 2.1
 *     Authorization Framework (draft 14)</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7662.html">OAuth 2.0 Token Introspection</a>
 */
@Provider
@Priority(Priorities.AUTHENTICATION)
public class TokenFilter implements ContainerRequestFilter {

  protected @Nullable Configuration configuration;

  /**
   * Constructs a filter without configuration.
   *
   * <p>When this constructor is used by a subclass, it must override {@link
   * #getTokenIntrospector()} and {@link #getTokenPrincipalProvider()}.
   */
  protected TokenFilter() {}

  public TokenFilter(@Context Configuration configuration) {
    this.configuration = requireNonNull(configuration);
  }

  /**
   * Returns the configured {@link TokenIntrospector}.
   *
   * @implSpec The default implementation gets it from the {@linkplain TokenFilter(Configuration)
   *     injected} configuration.
   */
  @ForOverride
  protected TokenIntrospector getTokenIntrospector() {
    return (TokenIntrospector)
        requireNonNull(
            requireNonNull(configuration).getProperty(TokenIntrospector.CONTEXT_ATTRIBUTE_NAME));
  }

  /**
   * Returns the configured {@link TokenPrincipalProvider}.
   *
   * @implSpec The default implementation gets it from the {@linkplain TokenFilter(Configuration)
   *     injected} configuration.
   */
  @ForOverride
  protected TokenPrincipalProvider getTokenPrincipalProvider() {
    var tokenPrincipalProvider =
        (TokenPrincipalProvider)
            requireNonNull(configuration)
                .getProperty(TokenPrincipalProvider.CONTEXT_ATTRIBUTE_NAME);
    if (tokenPrincipalProvider == null) {
      return SimpleTokenPrincipal.PROVIDER;
    }
    return tokenPrincipalProvider;
  }

  @Override
  public void filter(ContainerRequestContext requestContext) throws IOException {
    if (requestContext.getSecurityContext().getUserPrincipal() != null) {
      return;
    }
    new BearerTokenFilterHelper(getTokenIntrospector(), getTokenPrincipalProvider())
        .filter(
            requestContext.getMethod(),
            requestContext.getUriInfo().getAbsolutePath(),
            requestContext.getHeaders().getOrDefault(HttpHeaders.AUTHORIZATION, List.of()),
            requestContext.getHeaders().getOrDefault("DPoP", List.of()),
            getClientCertificate(requestContext),
            new TokenFilterHelper.FilterChain<IOException>() {

              @Override
              public void continueChain() {}

              @Override
              public void continueChain(
                  String authenticationScheme, TokenPrincipal tokenPrincipal) {
                requestContext.setSecurityContext(
                    wrapSecurityContext(
                        requestContext.getSecurityContext(), authenticationScheme, tokenPrincipal));
              }

              @Override
              public void sendError(
                  List<TokenSchemeError> errors, String message, @Nullable Throwable cause) {
                requestContext.abortWith(createErrorResponse(errors, message, cause));
              }

              @Override
              public void sendError(int statusCode, String message, @Nullable Throwable cause) {
                requestContext.abortWith(createErrorResponse(statusCode, message, cause));
              }
            });
  }

  @ForOverride
  protected Response createErrorResponse(
      List<TokenSchemeError> errors, String message, @Nullable Throwable cause) {
    if (cause != null) {
      log(message, cause);
    }
    var rb = Response.status(errors.getFirst().getHTTPStatusCode());
    for (var error : errors) {
      rb.header(HttpHeaders.WWW_AUTHENTICATE, error.toWWWAuthenticateHeader());
    }
    return rb.build();
  }

  @ForOverride
  protected Response createErrorResponse(
      int statusCode, String message, @Nullable Throwable cause) {
    if (cause != null) {
      log(message, cause);
    }
    return Response.status(statusCode).build();
  }

  @ForOverride
  protected void log(String message, @Nullable Throwable cause) {
    System.getLogger(TokenFilter.class.getName()).log(System.Logger.Level.WARNING, message, cause);
  }

  private SecurityContext wrapSecurityContext(
      SecurityContext securityContext, String authenticationScheme, TokenPrincipal tokenPrincipal) {
    return new SecurityContext() {
      @Override
      public Principal getUserPrincipal() {
        return tokenPrincipal;
      }

      @Override
      public boolean isUserInRole(String role) {
        return tokenPrincipal.hasRole(role);
      }

      @Override
      public boolean isSecure() {
        return securityContext.isSecure();
      }

      @Override
      public String getAuthenticationScheme() {
        return authenticationScheme;
      }
    };
  }

  private @Nullable X509Certificate getClientCertificate(ContainerRequestContext requestContext) {
    if (requestContext.getProperty(TokenFilterHelper.X509_CERTIFICATE_REQUEST_ATTRIBUTE_NAME)
            instanceof X509Certificate[] certs
        && certs.length > 0) {
      return certs[0];
    }
    return null;
  }
}
