/*
 * Copyright © 2026 Thomas Broyer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.ltgt.oauth.servlet;

import static java.util.Objects.requireNonNull;

import com.google.errorprone.annotations.ForOverride;
import com.google.errorprone.annotations.OverridingMethodsMustInvokeSuper;
import com.nimbusds.oauth2.sdk.token.TokenSchemeError;
import com.nimbusds.openid.connect.sdk.Nonce;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpFilter;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletResponseWrapper;
import java.io.IOException;
import java.net.URI;
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import net.ltgt.oauth.common.SimpleTokenPrincipal;
import net.ltgt.oauth.common.TokenErrorHelper;
import net.ltgt.oauth.common.TokenFilterHelper;
import net.ltgt.oauth.common.TokenIntrospector;
import net.ltgt.oauth.common.TokenPrincipal;
import net.ltgt.oauth.common.TokenPrincipalProvider;
import net.ltgt.oauth.common.TokenTypeSupport;
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
  private TokenTypeSupport tokenFilterHelperFactory;
  private TokenFilterHelper tokenFilterHelper;

  public TokenFilter() {}

  /**
   * Constructs a filter with the given token introspector and token principal provider, and a
   * {@code Bearer} token filter helper factory.
   *
   * <p>When this constructor is used, the servlet context attributes won't be read.
   */
  public TokenFilter(
      TokenIntrospector tokenIntrospector, TokenPrincipalProvider tokenPrincipalProvider) {
    this(tokenIntrospector, tokenPrincipalProvider, TokenTypeSupport.BEARER);
  }

  /**
   * Constructs a filter with the given token introspector, token principal provider, and token
   * filter helper factory.
   *
   * <p>When this constructor is used, the servlet context attributes won't be read.
   */
  public TokenFilter(
      TokenIntrospector tokenIntrospector,
      TokenPrincipalProvider tokenPrincipalProvider,
      TokenTypeSupport tokenFilterHelperFactory) {
    this.tokenIntrospector = requireNonNull(tokenIntrospector);
    this.tokenPrincipalProvider = requireNonNull(tokenPrincipalProvider);
    this.tokenFilterHelperFactory = requireNonNull(tokenFilterHelperFactory);
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
    if (tokenFilterHelperFactory == null) {
      tokenFilterHelperFactory =
          (TokenTypeSupport)
              getServletContext().getAttribute(TokenTypeSupport.CONTEXT_ATTRIBUTE_NAME);
    }
    if (tokenFilterHelperFactory == null) {
      tokenFilterHelperFactory = TokenTypeSupport.BEARER;
    }
    this.tokenFilterHelper =
        tokenFilterHelperFactory.create(tokenIntrospector, tokenPrincipalProvider);
  }

  @Override
  protected void doFilter(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws IOException, ServletException {
    if (req.getUserPrincipal() != null) {
      chain.doFilter(req, res);
      return;
    }
    req.setAttribute(
        TokenErrorHelper.REQUEST_ATTRIBUTE_NAME, new TokenErrorHelper(tokenFilterHelper));
    tokenFilterHelper.filter(
        req.getMethod(),
        URI.create(req.getRequestURL().toString()),
        Collections.list(req.getHeaders("Authorization")),
        Collections.list(req.getHeaders(TokenFilterHelper.DPOP_HEADER_NAME)),
        getClientCertificate(req),
        new TokenFilterHelper.FilterChain<ServletException>() {

          @Override
          public void continueChain(@Nullable Nonce dpopNonce)
              throws IOException, ServletException {
            chain.doFilter(req, maybeWrapResponse(res, dpopNonce));
          }

          @Override
          public void continueChain(
              String authenticationScheme, TokenPrincipal tokenPrincipal, @Nullable Nonce dpopNonce)
              throws IOException, ServletException {
            chain.doFilter(
                wrapRequest(req, authenticationScheme, tokenPrincipal),
                maybeWrapResponse(res, dpopNonce));
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors,
              @Nullable Nonce dpopNonce,
              String message,
              @Nullable Throwable cause)
              throws IOException, ServletException {
            TokenFilter.this.sendError(res, errors, dpopNonce, message, cause);
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
      HttpServletResponse res,
      List<TokenSchemeError> errors,
      @Nullable Nonce dpopNonce,
      String message,
      @Nullable Throwable cause)
      throws IOException, ServletException {
    if (cause != null) {
      log(message, cause);
    }
    res.reset();
    res.setStatus(errors.getFirst().getHTTPStatusCode());
    for (var error : errors) {
      res.addHeader("WWW-Authenticate", error.toWWWAuthenticateHeader());
    }
    if (dpopNonce != null) {
      res.setHeader(TokenFilterHelper.DPOP_NONCE_HEADER_NAME, dpopNonce.getValue());
    }
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

  private HttpServletResponse maybeWrapResponse(
      HttpServletResponse res, @Nullable Nonce dpopNonce) {
    if (dpopNonce == null) {
      return res;
    }
    res.setHeader(TokenFilterHelper.DPOP_NONCE_HEADER_NAME, dpopNonce.getValue());
    return new HttpServletResponseWrapper(res) {
      @Override
      public void reset() {
        super.reset();
        res.setHeader(TokenFilterHelper.DPOP_NONCE_HEADER_NAME, dpopNonce.getValue());
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
