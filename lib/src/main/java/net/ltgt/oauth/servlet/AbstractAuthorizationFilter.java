package net.ltgt.oauth.servlet;

import com.google.errorprone.annotations.ForOverride;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Base class for filters that send an error when the token is not authorized.
 *
 * <p>Requests that are authorized (and pass down the filter chain) are additionally marked with the
 * {@link #IS_PRIVATE_REQUEST_ATTRIBUTE_NAME} {@linkplain HttpServletRequest#getAttribute
 * attribute}.
 *
 * <p>Subclasses should be installed <i>after</i> the {@link TokenFilter}.
 *
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-14.html">The OAuth 2.1
 *     Authorization Framework (draft 14)</a>
 * @see TokenFilter
 */
public abstract class AbstractAuthorizationFilter extends HttpFilter {
  public static final String IS_PRIVATE_REQUEST_ATTRIBUTE_NAME =
      AbstractAuthorizationFilter.class.getName() + ".is_private";

  @Override
  protected void doFilter(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws IOException, ServletException {
    if (isAuthorized(req)) {
      req.setAttribute(IS_PRIVATE_REQUEST_ATTRIBUTE_NAME, true);
      super.doFilter(req, res, chain);
      return;
    }
    sendUnauthorized(req, res);
  }

  /**
   * Returns whether the token is authorized.
   *
   * <p>Implementations should only use the request's {@link HttpServletRequest#getUserPrincipal()
   * getUserPrincipal()} and/or {@link HttpServletRequest#isUserInRole(String) isUserInRole()}.
   */
  @ForOverride
  protected abstract boolean isAuthorized(HttpServletRequest req);

  /**
   * This method is called whenever the token is not authorized.
   *
   * <p>This implementation calls {@link #sendForbidden} whenever the user is authenticated, and
   * defers to {@link #doSendUnauthorized} otherwise.
   */
  @ForOverride
  protected void sendUnauthorized(HttpServletRequest req, HttpServletResponse res)
      throws IOException, ServletException {
    if (req.getUserPrincipal() == null) {
      doSendUnauthorized(req, res);
    } else {
      sendForbidden(req, res);
    }
  }

  /**
   * This method is called whenever the user is not authenticated.
   *
   * <p>The default implementation is equivalent to {@code sendError(res,
   * BearerTokenError.MISSING_TOKEN)}.
   *
   * @see #sendError
   */
  @ForOverride
  protected void doSendUnauthorized(HttpServletRequest req, HttpServletResponse res)
      throws IOException, ServletException {
    sendError(res, BearerTokenError.MISSING_TOKEN);
  }

  /**
   * Sends an error response corresponding to the {@link BearerTokenError}.
   *
   * <p>The default implementation {@linkplain HttpServletResponse#reset() resets} the response,
   * then sets the {@linkplain HttpServletResponse#setStatus status code} to the {@linkplain
   * BearerTokenError#getHTTPStatusCode() error's status code}, and adds a {@code WWW-Authenticate}
   * header from {@linkplain BearerTokenError#toWWWAuthenticateHeader() the error}.
   */
  protected void sendError(HttpServletResponse res, BearerTokenError error)
      throws IOException, ServletException {
    res.reset();
    res.setStatus(error.getHTTPStatusCode());
    res.setHeader("WWW-Authenticate", error.toWWWAuthenticateHeader());
  }

  /**
   * This method is called whenever the request is authenticated but not authorized.
   *
   * <p>The default implementation simply calls {@code res.sendError(SC_FORBIDDEN)}.
   *
   * <p>A subclass checking the token's scopes, for instance, would likely override this method to
   * call {@link #sendError} with a configured {@link BearerTokenError#INSUFFICIENT_SCOPE} error.
   */
  @ForOverride
  protected void sendForbidden(HttpServletRequest req, HttpServletResponse res)
      throws IOException, ServletException {
    res.sendError(HttpServletResponse.SC_FORBIDDEN);
  }
}
