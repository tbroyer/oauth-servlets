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
    final var dpopNonce = extractDPoPNonce(dpopProof);
    final var currentNonce = checkDPoPNonce(dpopNonceSupplier, dpopNonce);
    try {
      verifier.verify(
          method,
          uri,
          new DPoPIssuer(introspectionResponse.getClientID()),
          dpopProof,
          token,
          introspectionResponse.getJWKThumbprintConfirmation(),
          // we checked the nonce above, so "fake" it here by checking it against itself
          dpopNonce);
    } catch (AccessTokenValidationException | InvalidDPoPProofException | JOSEException e) {
      throw new DPoPException(DPoPTokenError.INVALID_DPOP_PROOF, null, "Invalid DPoP proof", e);
    }
    return Objects.equals(currentNonce, dpopNonce) ? null : currentNonce;
  }

  private static @Nullable Nonce extractDPoPNonce(SignedJWT dpopProof) throws DPoPException {
    try {
      return Nonce.parse(dpopProof.getJWTClaimsSet().getStringClaim("nonce"));
    } catch (java.text.ParseException e) {
      throw new DPoPException(DPoPTokenError.INVALID_DPOP_PROOF, null, "Invalid DPoP proof", e);
    }
  }

  private static @Nullable Nonce checkDPoPNonce(
      @Nullable DPoPNonceSupplier dpopNonceSupplier, @Nullable Nonce dpopNonce)
      throws DPoPException {
    if (dpopNonceSupplier == null) {
      if (dpopNonce != null) {
        throw new DPoPException(
            DPoPTokenError.INVALID_DPOP_PROOF, null, "Invalid DPoP proof (extraneous nonce)", null);
      }
      return null;
    }
    var nonces = dpopNonceSupplier.getNonces();
    var currentNonce = nonces.getFirst();
    if (dpopNonce == null || !nonces.contains(dpopNonce)) {
      throw new DPoPException(
          DPoPTokenError.USE_DPOP_NONCE,
          currentNonce,
          "Invalid DPoP proof (missing or invalid nonce)",
          null);
    }
    return currentNonce;
  }
}
