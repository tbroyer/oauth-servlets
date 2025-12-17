package net.ltgt.oauth.common;

import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.oauth2.sdk.auth.X509CertificateConfirmation;
import java.security.cert.X509Certificate;
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
}
