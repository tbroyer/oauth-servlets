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

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPProofUse;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPProtectedResourceRequestVerifier;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
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
 * Authenticates the request using a DPoP token and introspecting it, if provided in the request.
 */
class DPoPTokenFilterHelper implements TokenFilterHelper {

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
     * optional single use checker and optional DPoP nonce supplier.
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
      return new DPoPTokenFilterHelper(
          requireNonNull(tokenIntrospector),
          requireNonNull(tokenPrincipalProvider),
          acceptedJWSAlgs,
          verifier,
          dpopNonceSupplier);
    }
  }

  private final TokenIntrospector tokenIntrospector;
  private final TokenPrincipalProvider tokenPrincipalProvider;
  private final DPoPProtectedResourceRequestVerifier verifier;
  private final Set<JWSAlgorithm> acceptedJWSAlgs;
  private final @Nullable DPoPNonceSupplier dpopNonceSupplier;

  private DPoPTokenFilterHelper(
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
    return List.of(DPoPTokenError.MISSING_TOKEN.setJWSAlgorithms(acceptedJWSAlgs));
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
    assert authenticationScheme.equals(AccessTokenType.DPOP.getValue());
    return List.of(
        new DPoPTokenError(
            error.getCode(),
            error.getDescription(),
            error.getHTTPStatusCode(),
            error.getURI(),
            error.getRealm(),
            error.getScope(),
            acceptedJWSAlgs));
  }

  @Override
  public <E extends Exception> void filter(
      String method,
      URI uri,
      List<String> authorizations,
      List<String> dpopProofs,
      @Nullable X509Certificate clientCertificate,
      TokenFilterHelper.FilterChain<E> chain)
      throws IOException, E {
    var authorization =
        authorizations.stream()
            .filter(auth -> matchesAuthenticationScheme("dpop", auth))
            .findFirst()
            .orElse(null);
    if (authorization == null) {
      chain.continueChain(null);
      return;
    }

    DPoPAccessToken token;
    try {
      token = DPoPAccessToken.parse(authorization);
    } catch (ParseException e) {
      if (DPoPTokenError.MISSING_TOKEN.equals(e.getErrorObject())) {
        // this should never happen, but just in case
        token = null;
      } else {
        chain.sendError(
            List.of(((DPoPTokenError) e.getErrorObject()).setJWSAlgorithms(acceptedJWSAlgs)),
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

    // https://www.rfc-editor.org/rfc/rfc9449#section-4.3
    SignedJWT dpopProof;
    try {
      dpopProof = Utils.parseDPoPProof(dpopProofs);
    } catch (DPoPException e) {
      chain.sendError(
          List.of(e.getError().setJWSAlgorithms(acceptedJWSAlgs)),
          e.getCurrentNonce(),
          e.getMessage(),
          e.getCause());
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
      chain.sendError(
          List.of(DPoPTokenError.INVALID_TOKEN.setJWSAlgorithms(acceptedJWSAlgs)),
          null,
          "Invalid token",
          null);
      return;
    }

    Nonce currentNonce;
    try {
      currentNonce =
          checkDPoPProof(
              verifier, dpopNonceSupplier, method, uri, introspectionResponse, dpopProof, token);
    } catch (DPoPException e) {
      chain.sendError(
          List.of(e.getError().setJWSAlgorithms(acceptedJWSAlgs)),
          e.getCurrentNonce(),
          e.getMessage(),
          e.getCause());
      return;
    }

    String errorMessage =
        checkMTLSBoundToken(
            introspectionResponse.getX509CertificateConfirmation(), clientCertificate);
    if (errorMessage != null) {
      chain.sendError(List.of(BearerTokenError.INVALID_TOKEN), currentNonce, errorMessage, null);
      return;
    }

    var tokenPrincipal = tokenPrincipalProvider.getTokenPrincipal(introspectionResponse);
    if (tokenPrincipal != null) {
      chain.continueChain(AccessTokenType.DPOP.getValue(), tokenPrincipal, currentNonce);
    } else {
      chain.continueChain(currentNonce);
    }
  }
}
