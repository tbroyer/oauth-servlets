package net.ltgt.oauth.rs;

import static java.util.Objects.requireNonNull;

import com.google.errorprone.annotations.ForOverride;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
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
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-12.html">The OAuth 2.1
 *     Authorization Framework (draft 12)</a>
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
   * <p>The default implementation gets it from the {@linkplain TokenFilter(Configuration) injected}
   * configuration.
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
   * <p>The default implementation gets it from the {@linkplain TokenFilter(Configuration) injected}
   * configuration.
   */
  @ForOverride
  protected TokenPrincipalProvider getTokenPrincipalProvider() {
    return (TokenPrincipalProvider)
        requireNonNull(
            requireNonNull(configuration)
                .getProperty(TokenPrincipalProvider.CONTEXT_ATTRIBUTE_NAME));
  }

  @Override
  public void filter(ContainerRequestContext requestContext) throws IOException {
    new TokenFilterHelper<IOException>(getTokenIntrospector(), getTokenPrincipalProvider()) {
      @Override
      protected void continueChain(@Nullable TokenPrincipal tokenPrincipal) {
        if (tokenPrincipal != null) {
          requestContext.setSecurityContext(
              wrapSecurityContext(requestContext.getSecurityContext(), tokenPrincipal));
        }
      }

      @Override
      protected void sendError(BearerTokenError error, String message, @Nullable Throwable cause) {
        requestContext.abortWith(createErrorResponse(error, message, cause));
      }

      @Override
      protected void sendError(int statusCode, String message, @Nullable Throwable cause) {
        requestContext.abortWith(createErrorResponse(statusCode, message, cause));
      }
    }.filter(
        requestContext.getSecurityContext().getUserPrincipal(),
        requestContext.getHeaders().getFirst(HttpHeaders.AUTHORIZATION));
  }

  @ForOverride
  protected Response createErrorResponse(
      BearerTokenError error, String message, @Nullable Throwable cause) {
    if (cause != null) {
      log(message, cause);
    }
    return Response.status(error.getHTTPStatusCode())
        .header(HttpHeaders.WWW_AUTHENTICATE, error.toWWWAuthenticateHeader())
        .build();
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
      SecurityContext securityContext, TokenPrincipal tokenPrincipal) {
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
        return "Bearer";
      }
    };
  }
}
