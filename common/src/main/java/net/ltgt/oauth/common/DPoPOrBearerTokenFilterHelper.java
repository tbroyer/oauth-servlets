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
import static net.ltgt.oauth.common.Utils.checkDPoPProof;
import static net.ltgt.oauth.common.Utils.checkMTLSBoundToken;
import static net.ltgt.oauth.common.Utils.isDPoPToken;
import static net.ltgt.oauth.common.Utils.matchesAuthenticationScheme;
import static net.ltgt.oauth.common.Utils.parseDPoPProof;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPProofUse;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPProtectedResourceRequestVerifier;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.oauth2.sdk.token.DPoPTokenError;
import com.nimbusds.oauth2.sdk.token.TokenSchemeError;
import com.nimbusds.oauth2.sdk.util.singleuse.SingleUseChecker;
import com.nimbusds.openid.connect.sdk.Nonce;
import java.io.IOException;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletionException;
import net.ltgt.oauth.common.Utils.DPoPException;
import org.jspecify.annotations.Nullable;

/**
 * Authenticates the request using either a DPoP token or a Bearer token, and introspecting it, if
 * provided in the request.
 */
class DPoPOrBearerTokenFilterHelper implements TokenFilterHelper {
  static class Factory implements TokenTypeSupport {

    public static final long DEFAULT_MAX_CLOCK_SKEW_SECONDS =
        DefaultJWTClaimsVerifier.DEFAULT_MAX_CLOCK_SKEW_SECONDS;
    public static final long DEFAULT_MAX_AGE_SECONDS = DEFAULT_MAX_CLOCK_SKEW_SECONDS;

    private final Set<JWSAlgorithm> acceptedJWSAlgs;
    private final DPoPProtectedResourceRequestVerifier verifier;
    private final @Nullable DPoPNonceSupplier dpopNonceSupplier;

    /**
     * Constructs a factory with the given accepted JWS algorithms, an optional single use checker,
     * and the default max clock skew and max age.
     */
    public Factory(
        Set<JWSAlgorithm> acceptedJWSAlgs,
        @Nullable SingleUseChecker<DPoPProofUse> singleUseChecker,
        @Nullable DPoPNonceSupplier dpopNonceSupplier) {
      this(
          acceptedJWSAlgs,
          DEFAULT_MAX_CLOCK_SKEW_SECONDS,
          DEFAULT_MAX_AGE_SECONDS,
          singleUseChecker,
          dpopNonceSupplier);
    }

    /**
     * Constructs a factory with the given accepted JWS algorithms, max clock skew, max age, and an
     * optional single use checker.
     */
    public Factory(
        Set<JWSAlgorithm> acceptedJWSAlgs,
        long maxClockSkewSeconds,
        long maxAgeSeconds,
        @Nullable SingleUseChecker<DPoPProofUse> singleUseChecker,
        @Nullable DPoPNonceSupplier dpopNonceSupplier) {
      this.acceptedJWSAlgs = acceptedJWSAlgs = Set.copyOf(acceptedJWSAlgs);
      this.verifier =
          new DPoPProtectedResourceRequestVerifier(
              acceptedJWSAlgs, maxClockSkewSeconds, maxAgeSeconds, singleUseChecker);
      this.dpopNonceSupplier = dpopNonceSupplier;
    }

    @Override
    public TokenFilterHelper create(
        TokenIntrospector tokenIntrospector, TokenPrincipalProvider tokenPrincipalProvider) {
      return new DPoPOrBearerTokenFilterHelper(
          requireNonNull(tokenIntrospector),
          requireNonNull(tokenPrincipalProvider),
          acceptedJWSAlgs,
          verifier,
          dpopNonceSupplier);
    }
  }

  private final TokenIntrospector tokenIntrospector;
  private final TokenPrincipalProvider tokenPrincipalProvider;
  private final Set<JWSAlgorithm> acceptedJWSAlgs;
  private final DPoPProtectedResourceRequestVerifier verifier;
  private final @Nullable DPoPNonceSupplier dpopNonceSupplier;

  private DPoPOrBearerTokenFilterHelper(
      TokenIntrospector tokenIntrospector,
      TokenPrincipalProvider tokenPrincipalProvider,
      Set<JWSAlgorithm> acceptedJWSAlgs,
      DPoPProtectedResourceRequestVerifier verifier,
      @Nullable DPoPNonceSupplier dpopNonceSupplier) {
    this.tokenIntrospector = tokenIntrospector;
    this.tokenPrincipalProvider = tokenPrincipalProvider;
    this.acceptedJWSAlgs = acceptedJWSAlgs;
    this.verifier = verifier;
    this.dpopNonceSupplier = dpopNonceSupplier;
  }

  @Override
  public List<TokenSchemeError> getUnauthorizedErrors() {
    return List.of(
        DPoPTokenError.MISSING_TOKEN.setJWSAlgorithms(acceptedJWSAlgs),
        BearerTokenError.MISSING_TOKEN);
  }

  @Override
  public @Nullable Nonce getDPoPNonce() {
    if (dpopNonceSupplier == null) {
      return null;
    }
    return dpopNonceSupplier.getNonces().getFirst();
  }

  @Override
  public List<TokenSchemeError> adaptError(String authenticationScheme, BearerTokenError error) {
    if (authenticationScheme.equals(AccessTokenType.DPOP.getValue())) {
      return List.of(
          new DPoPTokenError(
              error.getCode(),
              error.getDescription(),
              error.getHTTPStatusCode(),
              error.getURI(),
              error.getRealm(),
              error.getScope(),
              acceptedJWSAlgs),
          BearerTokenError.MISSING_TOKEN);
    }
    assert authenticationScheme.equals(AccessTokenType.BEARER.getValue());
    return List.of(error, DPoPTokenError.MISSING_TOKEN.setJWSAlgorithms(acceptedJWSAlgs));
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
    var dpopAuthorization =
        authorizations.stream()
            .filter(authorization -> matchesAuthenticationScheme("dpop", authorization))
            .findFirst()
            .orElse(null);
    var bearerAuthorization =
        authorizations.stream()
            .filter(authorization -> matchesAuthenticationScheme("bearer", authorization))
            .findFirst()
            .orElse(null);
    if (dpopAuthorization != null) {
      handleDPoPToken(
          method,
          uri,
          dpopAuthorization,
          bearerAuthorization,
          dpopProofs,
          clientCertificate,
          chain);
      return;
    }
    if (bearerAuthorization != null) {
      handleBearerToken(bearerAuthorization, clientCertificate, chain);
      return;
    }
    // dpopAuthorization == null && bearerAuthorization == null
    chain.continueChain(null);
  }

  private <E extends Exception> void handleDPoPToken(
      String method,
      URI uri,
      String dpopAuthorization,
      @Nullable String bearerAuthorization,
      List<String> dpopProofs,
      @Nullable X509Certificate clientCertificate,
      FilterChain<E> chain)
      throws IOException, E {
    DPoPAccessToken token;
    try {
      token = DPoPAccessToken.parse(dpopAuthorization);
    } catch (ParseException e) {
      if (DPoPTokenError.MISSING_TOKEN.equals(e.getErrorObject())) {
        // this should never happen, but just in case
        token = null;
      } else {
        sendError(
            chain,
            ((DPoPTokenError) e.getErrorObject()),
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
    // https://www.rfc-editor.org/rfc/rfc9449#section-7.2
    if (bearerAuthorization != null) {
      BearerAccessToken bearerToken;
      try {
        bearerToken = BearerAccessToken.parse(bearerAuthorization);
      } catch (ParseException e) {
        // ignore malformed header
        bearerToken = null;
      }
      if (bearerToken != null) {
        chain.sendError(
            List.of(
                DPoPTokenError.INVALID_REQUEST
                    .setJWSAlgorithms(acceptedJWSAlgs)
                    .setDescription("Multiple methods used to include access token"),
                BearerTokenError.INVALID_REQUEST.setDescription(
                    "Multiple methods used to include access token")),
            null,
            "Multiple methods used to include access token",
            null);
        return;
      }
    }

    // https://www.rfc-editor.org/rfc/rfc9449#section-4.3
    SignedJWT dpopProof;
    try {
      dpopProof = parseDPoPProof(dpopProofs);
    } catch (DPoPException e) {
      sendError(chain, e.getError(), e.getCurrentNonce(), e.getMessage(), e.getCause());
      return;
    }

    TokenIntrospectionSuccessResponse introspectionResponse;
    try {
      introspectionResponse = tokenIntrospector.introspect(token);
    } catch (CompletionException e) {
      chain.sendError(HTTPResponse.SC_SERVER_ERROR, "Error introspecting token", e.getCause());
      return;
    }
    if (introspectionResponse == null || !isDPoPToken(introspectionResponse)) {
      sendError(chain, DPoPTokenError.INVALID_TOKEN, null, "Invalid token", null);
      return;
    }

    Nonce currentNonce;
    try {
      currentNonce =
          checkDPoPProof(
              verifier, dpopNonceSupplier, method, uri, introspectionResponse, dpopProof, token);
    } catch (DPoPException e) {
      sendError(chain, e.getError(), e.getCurrentNonce(), e.getMessage(), e.getCause());
      return;
    }

    String errorMessage =
        checkMTLSBoundToken(
            introspectionResponse.getX509CertificateConfirmation(), clientCertificate);
    if (errorMessage != null) {
      sendError(chain, DPoPTokenError.INVALID_TOKEN, currentNonce, errorMessage, null);
      return;
    }

    var tokenPrincipal = tokenPrincipalProvider.getTokenPrincipal(introspectionResponse);
    if (tokenPrincipal != null) {
      chain.continueChain(AccessTokenType.DPOP.getValue(), tokenPrincipal, currentNonce);
    } else {
      chain.continueChain(currentNonce);
    }
  }

  private <E extends Exception> void handleBearerToken(
      String bearerAuthorization, @Nullable X509Certificate clientCertificate, FilterChain<E> chain)
      throws IOException, E {
    BearerAccessToken token;
    try {
      token = BearerAccessToken.parse(bearerAuthorization);
    } catch (ParseException e) {
      if (BearerTokenError.MISSING_TOKEN.equals(e.getErrorObject())) {
        // this should never happen, but just in case
        token = null;
      } else {
        sendError(
            chain,
            ((BearerTokenError) e.getErrorObject()),
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
      sendError(chain, BearerTokenError.INVALID_TOKEN, "Invalid token", null);
      return;
    }

    if (introspectionResponse.getJWKThumbprintConfirmation() != null) {
      sendError(
          chain,
          BearerTokenError.INVALID_TOKEN,
          "Downgraded usage of a DPoP-bound access token",
          null);
      return;
    }

    String errorMessage =
        checkMTLSBoundToken(
            introspectionResponse.getX509CertificateConfirmation(), clientCertificate);
    if (errorMessage != null) {
      sendError(chain, BearerTokenError.INVALID_TOKEN, errorMessage, null);
      return;
    }

    var tokenPrincipal = tokenPrincipalProvider.getTokenPrincipal(introspectionResponse);
    if (tokenPrincipal != null) {
      chain.continueChain(AccessTokenType.BEARER.getValue(), tokenPrincipal, null);
    } else {
      chain.continueChain(null);
    }
  }

  private <E extends Exception> void sendError(
      FilterChain<E> chain,
      DPoPTokenError error,
      @Nullable Nonce dpopNonce,
      String message,
      @Nullable Throwable cause)
      throws IOException, E {
    chain.sendError(
        List.of(error.setJWSAlgorithms(acceptedJWSAlgs), BearerTokenError.MISSING_TOKEN),
        dpopNonce,
        message,
        cause);
  }

  private <E extends Exception> void sendError(
      FilterChain<E> chain, BearerTokenError error, String message, @Nullable Throwable cause)
      throws IOException, E {
    chain.sendError(
        List.of(error, DPoPTokenError.MISSING_TOKEN.setJWSAlgorithms(acceptedJWSAlgs)),
        null,
        message,
        cause);
  }
}
