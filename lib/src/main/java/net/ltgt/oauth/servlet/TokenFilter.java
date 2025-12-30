package net.ltgt.oauth.servlet;

import static java.util.Objects.requireNonNull;

import com.google.errorprone.annotations.ForOverride;
import com.google.errorprone.annotations.OverridingMethodsMustInvokeSuper;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Principal;
import java.security.cert.X509Certificate;
import net.ltgt.oauth.common.SimpleTokenPrincipal;
import net.ltgt.oauth.common.TokenFilterHelper;
import net.ltgt.oauth.common.TokenIntrospector;
import net.ltgt.oauth.common.TokenPrincipal;
import net.ltgt.oauth.common.TokenPrincipalProvider;
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
 * @see <a href="https://www.ietf.org/archive/id/draft-ietf-oauth-v2-1-14.html">The OAuth 2.1
 *     Authorization Framework (draft 14)</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7662.html">OAuth 2.0 Token Introspection</a>
 */
public class TokenFilter extends HttpFilter {
  private TokenIntrospector tokenIntrospector;
  private TokenPrincipalProvider tokenPrincipalProvider;
  private TokenFilterHelper tokenFilterHelper;

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
    this.tokenFilterHelper = new TokenFilterHelper(tokenIntrospector, tokenPrincipalProvider);
  }

  @Override
  protected void doFilter(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws IOException, ServletException {
    if (req.getUserPrincipal() != null) {
      chain.doFilter(req, res);
      return;
    }
    tokenFilterHelper.filter(
        req.getHeader("Authorization"),
        getClientCertificate(req),
        new TokenFilterHelper.FilterChain<ServletException>() {

          @Override
          public void continueChain() throws IOException, ServletException {
            chain.doFilter(req, res);
          }

          @Override
          public void continueChain(String authenticationScheme, TokenPrincipal tokenPrincipal)
              throws IOException, ServletException {
            chain.doFilter(wrapRequest(req, authenticationScheme, tokenPrincipal), res);
          }

          @Override
          public void sendError(BearerTokenError error, String message, @Nullable Throwable cause)
              throws IOException, ServletException {
            TokenFilter.this.sendError(res, error, message, cause);
          }

          @Override
          public void sendError(int statusCode, String message, @Nullable Throwable cause)
              throws IOException, ServletException {
            TokenFilter.this.sendError(res, statusCode, message, cause);
          }
        });
  }

  @ForOverride
  protected void sendError(
      HttpServletResponse res, BearerTokenError error, String message, @Nullable Throwable cause)
      throws IOException, ServletException {
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

  private HttpServletRequest wrapRequest(
      HttpServletRequest req, String authenticationScheme, TokenPrincipal tokenPrincipal) {
    return new HttpServletRequestWrapper(req) {
      @Override
      public String getAuthType() {
        return authenticationScheme;
      }

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

  private @Nullable X509Certificate getClientCertificate(HttpServletRequest req) {
    if (req.getAttribute(TokenFilterHelper.X509_CERTIFICATE_REQUEST_ATTRIBUTE_NAME)
            instanceof X509Certificate[] certs
        && certs.length > 0) {
      return certs[0];
    }
    return null;
  }
}
