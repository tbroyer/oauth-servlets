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
package net.ltgt.oauth.rs;

import static java.util.Objects.requireNonNull;

import com.google.errorprone.annotations.ForOverride;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.oauth2.sdk.token.TokenSchemeError;
import com.nimbusds.openid.connect.sdk.Nonce;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import java.io.IOException;
import java.util.List;
import net.ltgt.oauth.common.TokenErrorHelper;
import org.jspecify.annotations.Nullable;

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
    requestContext.abortWith(createUnauthorizedResponse(requestContext));
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
  protected Response createUnauthorizedResponse(ContainerRequestContext requestContext) {
    if (requestContext.getSecurityContext().getUserPrincipal() == null) {
      return doCreateUnauthorizedResponse(requestContext);
    } else {
      return createForbiddenResponse(requestContext);
    }
  }

  /**
   * This method is called whenever the user is not authenticated.
   *
   * @implSpec The default implementation calls {@link #createErrorResponse(SecurityContext, List,
   *     Nonce)} with the errors from {@link TokenErrorHelper#getUnauthorizedErrors()} and DPoP
   *     nonce from {@link TokenErrorHelper#getDPoPNonce()}.
   */
  @ForOverride
  protected Response doCreateUnauthorizedResponse(ContainerRequestContext requestContext) {
    var tokenErrorHelper = getTokenErrorHelper(requestContext);
    return createErrorResponse(
        requestContext.getSecurityContext(),
        tokenErrorHelper.getUnauthorizedErrors(),
        tokenErrorHelper.getDPoPNonce());
  }

  /**
   * Creates an error response corresponding to the {@link BearerTokenError}.
   *
   * @implSpec The default implementation {@linkplain TokenErrorHelper#adaptError adapts} the error
   *     and then passes it to {@link #createErrorResponse(SecurityContext, List, Nonce)} along with
   *     a {@code null} nonce.
   */
  protected Response createErrorResponse(
      ContainerRequestContext requestContext, BearerTokenError error) {
    return createErrorResponse(
        requestContext.getSecurityContext(),
        getTokenErrorHelper(requestContext)
            .adaptError(requestContext.getSecurityContext().getAuthenticationScheme(), error),
        null);
  }

  /**
   * Creates an error response corresponding to the {@link BearerTokenError}.
   *
   * @implSpec The default implementation sets the {@linkplain Response#getStatus status code} to
   *     the {@linkplain TokenSchemeError#getHTTPStatusCode() first error's status code}, and adds
   *     {@link HttpHeaders#WWW_AUTHENTICATE WWW-Authenticate} headers from {@linkplain
   *     BearerTokenError#toWWWAuthenticateHeader() the errors} and an optional {@code DPoP-Nonce}
   *     header.
   */
  @ForOverride
  protected Response createErrorResponse(
      SecurityContext securityContext, List<TokenSchemeError> errors, @Nullable Nonce dpopNonce) {
    var rb = Response.status(errors.getFirst().getHTTPStatusCode());
    for (TokenSchemeError error : errors) {
      rb.header(HttpHeaders.WWW_AUTHENTICATE, error.toWWWAuthenticateHeader());
    }
    if (dpopNonce != null) {
      rb.header(TokenErrorHelper.DPOP_NONCE_HEADER_NAME, dpopNonce.getValue());
    }
    return rb.build();
  }

  /**
   * This method is called whenever the request is authenticated but not authorized.
   *
   * @implSpec
   *     <p>The default implementation creates a response with only the status set (to {@link
   *     Response.Status#FORBIDDEN FORBIDDEN}).
   *     <p>A subclass checking the token's scopes, for instance, would likely override this method
   *     to call {@link #createErrorResponse} with a configured {@link
   *     BearerTokenError#INSUFFICIENT_SCOPE} error.
   */
  @ForOverride
  protected Response createForbiddenResponse(ContainerRequestContext requestContext) {
    return Response.status(Response.Status.FORBIDDEN).build();
  }

  private TokenErrorHelper getTokenErrorHelper(ContainerRequestContext requestContext) {
    return requireNonNull(
        (TokenErrorHelper) requestContext.getProperty(TokenErrorHelper.REQUEST_ATTRIBUTE_NAME),
        "The filter is not behind a token filter (like BearerTokenFilter)");
  }
}
