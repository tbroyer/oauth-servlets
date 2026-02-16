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
package net.ltgt.oauth.common;

import static java.util.Objects.requireNonNull;
import static net.ltgt.oauth.common.Utils.checkMTLSBoundToken;
import static net.ltgt.oauth.common.Utils.matchesAuthenticationScheme;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.oauth2.sdk.token.TokenSchemeError;
import com.nimbusds.openid.connect.sdk.Nonce;
import java.io.IOException;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.CompletionException;
import org.jspecify.annotations.Nullable;

class BearerTokenFilterHelper implements TokenFilterHelper {

  private final TokenIntrospector tokenIntrospector;
  private final TokenPrincipalProvider tokenPrincipalProvider;

  BearerTokenFilterHelper(
      TokenIntrospector tokenIntrospector, TokenPrincipalProvider tokenPrincipalProvider) {
    this.tokenIntrospector = requireNonNull(tokenIntrospector);
    this.tokenPrincipalProvider = requireNonNull(tokenPrincipalProvider);
  }

  @Override
  public List<TokenSchemeError> getUnauthorizedErrors() {
    return List.of(BearerTokenError.MISSING_TOKEN);
  }

  @Override
  public @Nullable Nonce getDPoPNonce() {
    return null;
  }

  @Override
  public List<TokenSchemeError> adaptError(String authenticationScheme, BearerTokenError error) {
    assert authenticationScheme.equals(AccessTokenType.BEARER.getValue());
    return List.of(error);
  }

  @Override
  public <E extends Exception> void filter(
      String method,
      URI uri,
      List<String> authorizations,
      List<String> dpopProofs,
      @Nullable X509Certificate clientCertificate,
      FilterChain<E> chain)
      throws IOException, E {
    var authorization =
        authorizations.stream()
            .filter(auth -> matchesAuthenticationScheme("bearer", auth))
            .findFirst()
            .orElse(null);
    if (authorization == null) {
      chain.continueChain(null);
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
        chain.sendError(
            List.of((BearerTokenError) e.getErrorObject()),
            null,
            "Error parsing the Authorization header",
            e);
        return;
      }
    }
    if (token == null) {
      chain.continueChain(null);
      return;
    }
    TokenIntrospectionSuccessResponse introspectionResponse;
    try {
      introspectionResponse = tokenIntrospector.introspect(token);
    } catch (CompletionException e) {
      chain.sendError(HTTPResponse.SC_SERVER_ERROR, "Error introspecting token", e.getCause());
      return;
    }
    if (introspectionResponse == null) {
      chain.sendError(List.of(BearerTokenError.INVALID_TOKEN), null, "Invalid token", null);
      return;
    }
    String errorMessage =
        checkMTLSBoundToken(
            introspectionResponse.getX509CertificateConfirmation(), clientCertificate);
    if (errorMessage != null) {
      chain.sendError(List.of(BearerTokenError.INVALID_TOKEN), null, errorMessage, null);
      return;
    }
    var tokenPrincipal = tokenPrincipalProvider.getTokenPrincipal(introspectionResponse);
    if (tokenPrincipal != null) {
      chain.continueChain(AccessTokenType.BEARER.getValue(), tokenPrincipal, null);
    } else {
      chain.continueChain(null);
    }
  }
}
