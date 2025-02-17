package net.ltgt.oauth.servlet;

import static java.util.Objects.requireNonNull;

import com.google.errorprone.annotations.ForOverride;
import com.google.errorprone.annotations.OverridingMethodsMustInvokeSuper;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.util.concurrent.CompletionException;
import org.jspecify.annotations.Nullable;

/**
 * Authenticates the request using a Bearer token and introspecting it, if provided in the request.
 *
 * <p>Initializes the request's {@link HttpServletRequest#getUserPrincipal() getUserPrincipal()} and
 * {@link HttpServletRequest#getRemoteUser() getRemoteUser()}, and implements its {@link
 * HttpServletRequest#isUserInRole isUserInRole(String)} for other filters and servlets down the
 * chain. The user principal will be created by the {@link TokenPrincipalProvider} present in the
 * {@link jakarta.servlet.ServletContext ServletContext}.
 *
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-12.html">The OAuth 2.1
 *     Authorization Framework (draft 12)</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7662.html">OAuth 2.0 Token Introspection</a>
 */
public class TokenFilter extends HttpFilter {
  private TokenIntrospector tokenIntrospector;
  private TokenPrincipalProvider tokenPrincipalProvider;

  public TokenFilter() {}

  /**
   * Constructs a filter with the given configuration, token introspector, and token principal
   * provider.
   *
   * <p>When this constructor is used, the servlet context attributes won't be read.
   */
  public TokenFilter(
      TokenIntrospector tokenIntrospector, TokenPrincipalProvider tokenPrincipalProvider) {
    this.tokenIntrospector = requireNonNull(tokenIntrospector);
    this.tokenPrincipalProvider = requireNonNull(tokenPrincipalProvider);
  }

  @OverridingMethodsMustInvokeSuper
  @Override
  public void init() throws ServletException {
    if (tokenIntrospector == null) {
      tokenIntrospector =
          (TokenIntrospector)
              getServletContext().getAttribute(TokenIntrospector.CONTEXT_ATTRIBUTE_NAME);
    }
    requireNonNull(tokenIntrospector, "tokenIntrospector");
    if (tokenPrincipalProvider == null) {
      tokenPrincipalProvider =
          (TokenPrincipalProvider)
              getServletContext().getAttribute(TokenPrincipalProvider.CONTEXT_ATTRIBUTE_NAME);
    }
    if (tokenPrincipalProvider == null) {
      tokenPrincipalProvider = SimpleTokenPrincipal.PROVIDER;
    }
  }

  @Override
  protected void doFilter(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws IOException, ServletException {
    if (req.getUserPrincipal() != null) {
      // Already authenticated
      super.doFilter(req, res, chain);
      return;
    }
    var authorization = req.getHeader("Authorization");
    if (authorization == null
        || !authorization.regionMatches(true, 0, "bearer", 0, 6)
        || (authorization.length() != 6 && authorization.charAt(6) != ' ')) {
      super.doFilter(req, res, chain);
      return;
    }
    BearerAccessToken token;
    try {
      token = BearerAccessToken.parse(authorization);
    } catch (ParseException e) {
      if (BearerTokenError.MISSING_TOKEN.equals(e.getErrorObject())) {
        // This should never happen, but just in case
        token = null;
      } else {
        sendError(
            res,
            ((BearerTokenError) e.getErrorObject()),
            "Error parsing the Authorization header",
            e);
        return;
      }
    }
    if (token != null) {
      TokenIntrospectionSuccessResponse introspectionResponse;
      try {
        introspectionResponse = tokenIntrospector.introspect(token);
      } catch (CompletionException e) {
        sendError(
            res,
            HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
            "Error introspecting token",
            e.getCause());
        return;
      }
      if (introspectionResponse == null) {
        sendError(res, BearerTokenError.INVALID_TOKEN, "Invalid token", null);
        return;
      }
      var tokenPrincipal = tokenPrincipalProvider.getTokenPrincipal(introspectionResponse);
      req = wrapRequest(req, tokenPrincipal);
    }
    super.doFilter(req, res, chain);
  }

  @ForOverride
  protected void sendError(
      HttpServletResponse res, BearerTokenError error, String message, @Nullable Throwable cause)
      throws IOException {
    if (cause != null) {
      log(message, cause);
    }
    res.reset();
    res.setStatus(error.getHTTPStatusCode());
    res.addHeader("WWW-Authenticate", error.toWWWAuthenticateHeader());
  }

  @ForOverride
  protected void sendError(
      HttpServletResponse resp, int statusCode, String message, @Nullable Throwable cause)
      throws IOException, ServletException {
    if (cause != null) {
      log(message, cause);
    }
    resp.sendError(statusCode, message);
  }

  @ForOverride
  protected void log(String message, Throwable cause) {
    // Same as GenericServlet.log()
    getServletContext().log(getFilterName() + ": " + message, cause);
  }

  private HttpServletRequest wrapRequest(HttpServletRequest req, TokenPrincipal tokenPrincipal) {
    return new HttpServletRequestWrapper(req) {
      @Override
      public String getRemoteUser() {
        return tokenPrincipal.getName();
      }

      @Override
      public Principal getUserPrincipal() {
        return tokenPrincipal;
      }

      @Override
      public boolean isUserInRole(String role) {
        return tokenPrincipal.hasRole(role);
      }
    };
  }
}
