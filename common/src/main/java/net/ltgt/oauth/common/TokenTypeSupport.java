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

import com.google.errorprone.annotations.RestrictedApi;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPProofUse;
import com.nimbusds.oauth2.sdk.util.singleuse.SingleUseChecker;
import java.util.Set;
import org.jspecify.annotations.Nullable;

/**
 * Called by {@code TokenFilter} (either at initialization time, or on each request) to create a
 * {@linkplain TokenFilterHelper platform-independent implementation} for the selected token
 * type(s).
 *
 * <p>An instance implementing this interface needs to be registered as a {@code ServletContext}
 * attribute or JAX-RS {@code Configuration} property under the name {@link
 * #CONTEXT_ATTRIBUTE_NAME}. If no such instance is configured, {@code TokenFilter} will default to
 * using {@link #BEARER}.
 *
 * <p>Use the {@link #BEARER} constant or one of the static methods to create an instance
 * implementing this interface.
 */
public interface TokenTypeSupport {
  String CONTEXT_ATTRIBUTE_NAME = TokenTypeSupport.class.getName();

  /**
   * Authenticates the request using a Bearer token and introspecting it, if provided in the
   * request.
   */
  TokenTypeSupport BEARER = BearerTokenFilterHelper::new;

  /**
   * Authenticates the request using a DPoP token and introspecting it, if provided in the request,
   * using the given accepted JWS algorithms, an optional single use checker, and the default max
   * clock skew and max age.
   */
  static TokenTypeSupport dpop(
      Set<JWSAlgorithm> acceptedJWSAlgs,
      @Nullable SingleUseChecker<DPoPProofUse> singleUseChecker,
      @Nullable DPoPNonceSupplier dpopNonceSupplier) {
    return new DPoPTokenFilterHelper.Factory(acceptedJWSAlgs, singleUseChecker, dpopNonceSupplier);
  }

  /**
   * Authenticates the request using a DPoP token and introspecting it, if provided in the request,
   * using the given accepted JWS algorithms, max clock skew, max age, and an optional single use
   * checker and optional DPoP nonce supplier.
   */
  static TokenTypeSupport dpop(
      Set<JWSAlgorithm> acceptedJWSAlgs,
      long maxClockSkewSeconds,
      long maxAgeSeconds,
      @Nullable SingleUseChecker<DPoPProofUse> singleUseChecker,
      @Nullable DPoPNonceSupplier dpopNonceSupplier) {
    return new DPoPTokenFilterHelper.Factory(
        acceptedJWSAlgs, maxClockSkewSeconds, maxAgeSeconds, singleUseChecker, dpopNonceSupplier);
  }

  /**
   * Authenticates the request using either a DPoP token or a Bearer token, and introspecting it, if
   * provided in the request, using the given accepted JWS algorithms, an optional single use
   * checker, and the default max clock skew and max age.
   */
  static TokenTypeSupport dpopOrBearer(
      Set<JWSAlgorithm> acceptedJWSAlgs,
      @Nullable SingleUseChecker<DPoPProofUse> singleUseChecker,
      @Nullable DPoPNonceSupplier dpopNonceSupplier) {
    return new DPoPOrBearerTokenFilterHelper.Factory(
        acceptedJWSAlgs, singleUseChecker, dpopNonceSupplier);
  }

  /**
   * Authenticates the request using either a DPoP token or a Bearer token, and introspecting it, if
   * provided in the request, using the given accepted JWS algorithms, max clock skew, max age, and
   * an optional single use checker.
   */
  static TokenTypeSupport dpopOrBearer(
      Set<JWSAlgorithm> acceptedJWSAlgs,
      long maxClockSkewSeconds,
      long maxAgeSeconds,
      @Nullable SingleUseChecker<DPoPProofUse> singleUseChecker,
      @Nullable DPoPNonceSupplier dpopNonceSupplier) {
    return new DPoPOrBearerTokenFilterHelper.Factory(
        acceptedJWSAlgs, maxClockSkewSeconds, maxAgeSeconds, singleUseChecker, dpopNonceSupplier);
  }

  /**
   * Called by {@code TokenFilter} to create a new {@link TokenFilterHelper} instance with the given
   * token introspector and token principal provider.
   */
  @RestrictedApi(explanation = "Internal API", allowedOnPath = ".*/java/net/ltgt/oauth/.*")
  TokenFilterHelper create(
      TokenIntrospector tokenIntrospector, TokenPrincipalProvider tokenPrincipalProvider);
}
