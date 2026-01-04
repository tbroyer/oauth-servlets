package net.ltgt.oauth.rs;

import com.google.errorprone.annotations.ForOverride;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import java.io.IOException;

/**
 * Base class for filters that send an error when the token is not authorized.
 *
 * <p>Requests that are authorized (and pass down the filter chain) are additionally marked with the
 * {@link #IS_PRIVATE_REQUEST_PROPERTY_NAME} {@linkplain
 * jakarta.ws.rs.core.Configuration#getProperty property}.
 *
 * <p>Subclasses should be registered with a <i>higher</i> priority than the {@link TokenFilter}
 * ({@link jakarta.ws.rs.Priorities#AUTHENTICATION AUTHENTICATION}), most likely {@link
 * jakarta.ws.rs.Priorities#AUTHORIZATION AUTHORIZATION}.
 *
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-14.html">The OAuth 2.1
 *     Authorization Framework (draft 14)</a>
 * @see TokenFilter
 */
public abstract class AbstractAuthorizationFilter implements ContainerRequestFilter {
  public static final String IS_PRIVATE_REQUEST_PROPERTY_NAME =
      AbstractAuthorizationFilter.class.getName() + ".is_private";

  @Override
  public void filter(ContainerRequestContext requestContext) throws IOException {
    var securityContext = requestContext.getSecurityContext();
    if (isAuthorized(securityContext)) {
      requestContext.setProperty(IS_PRIVATE_REQUEST_PROPERTY_NAME, true);
      return;
    }
    requestContext.abortWith(createUnauthorizedResponse(securityContext));
  }

  /** Returns whether the token is authorized. */
  @ForOverride
  protected abstract boolean isAuthorized(SecurityContext securityContext);

  /**
   * This method is called whenever the token is not authorized.
   *
   * <p>This implementation calls {@link #createForbiddenResponse} whenever the user is
   * authenticated, and defers to {@link #doCreateUnauthorizedResponse} otherwise.
   */
  @ForOverride
  protected Response createUnauthorizedResponse(SecurityContext securityContext) {
    if (securityContext.getUserPrincipal() == null) {
      return doCreateUnauthorizedResponse(securityContext);
    } else {
      return createForbiddenResponse(securityContext);
    }
  }

  /**
   * This method is called whenever the user is not authenticated.
   *
   * <p>The default implementation is equivalent to {@code createErrorResponse(securityContext,
   * BearerTokenError.MISSING_TOKEN)}.
   *
   * @see #createErrorResponse
   */
  @ForOverride
  protected Response doCreateUnauthorizedResponse(SecurityContext securityContext) {
    return createErrorResponse(securityContext, BearerTokenError.MISSING_TOKEN);
  }

  /**
   * Creates an error response corresponding to the {@link BearerTokenError}.
   *
   * <p>The default implementation sets the {@linkplain Response#getStatus} status code} to the
   * {@linkplain BearerTokenError#getHTTPStatusCode() error's status code}, and adds a {@link
   * HttpHeaders#WWW_AUTHENTICATE WWW-Authenticate} header from {@linkplain
   * BearerTokenError#toWWWAuthenticateHeader() the error}.
   */
  protected Response createErrorResponse(SecurityContext securityContext, BearerTokenError error) {
    return Response.status(error.getHTTPStatusCode())
        .header(HttpHeaders.WWW_AUTHENTICATE, error.toWWWAuthenticateHeader())
        .build();
  }

  /**
   * This method is called whenever the request is authenticated but not authorized.
   *
   * <p>The default implementation creates a response with only the status set (to {@link
   * Response.Status#FORBIDDEN FORBIDDEN}).
   *
   * <p>A subclass checking the token's scopes, for instance, would likely override this method to
   * call {@link #createErrorResponse} with a configured {@link BearerTokenError#INSUFFICIENT_SCOPE}
   * error.
   */
  @ForOverride
  protected Response createForbiddenResponse(SecurityContext securityContext) {
    return Response.status(Response.Status.FORBIDDEN).build();
  }
}
