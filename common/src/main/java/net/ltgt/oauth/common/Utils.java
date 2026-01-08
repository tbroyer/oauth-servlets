package net.ltgt.oauth.common;

import static java.util.Objects.requireNonNullElse;

import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.auth.X509CertificateConfirmation;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;
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

  static <E extends Exception> @Nullable SignedJWT parseDPoPProof(
      List<String> dpopProofs, ErrorCallback<E> errorCallback) throws E, IOException {
    if (dpopProofs.isEmpty()) {
      errorCallback.sendError("Missing DPoP proof", null);
      return null;
    } else if (dpopProofs.size() > 1) {
      errorCallback.sendError("Too many DPoP proofs", null);
      return null;
    }
    SignedJWT dpopProof;
    try {
      dpopProof = SignedJWT.parse(dpopProofs.getFirst());
    } catch (java.text.ParseException e) {
      errorCallback.sendError("Error parsing the DPoP proof", e);
      return null;
    }
    return dpopProof;
  }
}
