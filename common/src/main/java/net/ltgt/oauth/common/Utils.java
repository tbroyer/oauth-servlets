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
import static java.util.Objects.requireNonNullElse;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.auth.X509CertificateConfirmation;
import com.nimbusds.oauth2.sdk.dpop.verifiers.AccessTokenValidationException;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPIssuer;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPProtectedResourceRequestVerifier;
import com.nimbusds.oauth2.sdk.dpop.verifiers.InvalidDPoPNonceException;
import com.nimbusds.oauth2.sdk.dpop.verifiers.InvalidDPoPProofException;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.oauth2.sdk.token.DPoPTokenError;
import com.nimbusds.openid.connect.sdk.Nonce;
import java.io.IOException;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.jspecify.annotations.Nullable;

class Utils {
  private Utils() {
    // non-instantiable
  }

  static boolean matchesAuthenticationScheme(String authenticationScheme, String authorization) {
    var len = authenticationScheme.length();
    return authorization.regionMatches(true, 0, authenticationScheme, 0, len)
        && (authorization.length() == len || authorization.charAt(len) == ' ');
  }

  static @Nullable String checkMTLSBoundToken(
      @Nullable X509CertificateConfirmation x509CertificateConfirmation,
      @Nullable X509Certificate clientCertificate) {
    if (x509CertificateConfirmation != null) {
      if (clientCertificate == null) {
        return "No client certificate presented";
      }
      if (!x509CertificateConfirmation
          .getValue()
          .equals(X509CertUtils.computeSHA256Thumbprint(clientCertificate))) {
        return "Presented client certificate doesn't match sender-constrained access token";
      }
    }
    return null;
  }

  static boolean isDPoPToken(TokenIntrospectionSuccessResponse introspectionResponse) {
    // token_type must be DPOP if present
    return AccessTokenType.DPOP.equals(
            requireNonNullElse(introspectionResponse.getTokenType(), AccessTokenType.DPOP))
        // introspection response must have cnf.jkt
        && introspectionResponse.getJWKThumbprintConfirmation() != null;
  }

  @FunctionalInterface
  interface ErrorCallback<E extends Exception> {
    void sendError(String message, @Nullable Throwable cause) throws E, IOException;
  }

  static class DPoPException extends Exception {
    private final DPoPTokenError error;
    private final @Nullable Nonce currentNonce;

    DPoPException(
        DPoPTokenError error,
        @Nullable Nonce currentNonce,
        String message,
        @Nullable Throwable cause) {
      super(message, cause);
      this.error = error;
      this.currentNonce = currentNonce;
    }

    public DPoPTokenError getError() {
      return error;
    }

    public @Nullable Nonce getCurrentNonce() {
      return currentNonce;
    }

    @Override
    public String getMessage() {
      return requireNonNull(super.getMessage());
    }
  }

  static SignedJWT parseDPoPProof(List<String> dpopProofs) throws DPoPException {
    if (dpopProofs.isEmpty()) {
      throw new DPoPException(DPoPTokenError.INVALID_DPOP_PROOF, null, "Missing DPoP proof", null);
    } else if (dpopProofs.size() > 1) {
      throw new DPoPException(
          DPoPTokenError.INVALID_DPOP_PROOF, null, "Too many DPoP proofs", null);
    }
    SignedJWT dpopProof;
    try {
      dpopProof = SignedJWT.parse(dpopProofs.getFirst());
    } catch (java.text.ParseException e) {
      throw new DPoPException(
          DPoPTokenError.INVALID_DPOP_PROOF, null, "Error parsing the DPoP proof", e);
    }
    return dpopProof;
  }

  static @Nullable Nonce checkDPoPProof(
      DPoPProtectedResourceRequestVerifier verifier,
      @Nullable DPoPNonceSupplier dpopNonceSupplier,
      String method,
      URI uri,
      TokenIntrospectionSuccessResponse introspectionResponse,
      SignedJWT dpopProof,
      DPoPAccessToken token)
      throws DPoPException {
    final var nonces =
        dpopNonceSupplier == null ? null : requireNonNull(dpopNonceSupplier.getNonces());
    final var currentNonce = nonces == null ? null : requireNonNull(nonces.getFirst());
    try {
      verifier.verify(
          method,
          uri,
          new DPoPIssuer(introspectionResponse.getClientID()),
          dpopProof,
          token,
          introspectionResponse.getJWKThumbprintConfirmation(),
          nonces == null ? null : Set.copyOf(nonces),
          null);
    } catch (InvalidDPoPNonceException e) {
      if (currentNonce == null) {
        throw new DPoPException(
            DPoPTokenError.INVALID_DPOP_PROOF, null, "Invalid DPoP proof (extraneous nonce)", null);
      }
      throw new DPoPException(
          DPoPTokenError.USE_DPOP_NONCE,
          currentNonce,
          "Invalid DPoP proof (missing or invalid nonce)",
          null);
    } catch (AccessTokenValidationException | InvalidDPoPProofException | JOSEException e) {
      throw new DPoPException(DPoPTokenError.INVALID_DPOP_PROOF, null, "Invalid DPoP proof", e);
    }
    if (currentNonce == null) {
      return null;
    }
    final var dpopNonce = extractDPoPNonce(dpopProof);
    return Objects.equals(currentNonce, dpopNonce) ? null : currentNonce;
  }

  private static @Nullable Nonce extractDPoPNonce(SignedJWT dpopProof) throws DPoPException {
    try {
      return Nonce.parse(dpopProof.getJWTClaimsSet().getStringClaim("nonce"));
    } catch (java.text.ParseException e) {
      // This should never happen as the DPoP proof has already been validated
      throw new DPoPException(DPoPTokenError.INVALID_DPOP_PROOF, null, "Invalid DPoP proof", e);
    }
  }
}
