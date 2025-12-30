package net.ltgt.oauth.common;

import com.google.errorprone.annotations.RestrictedApi;
import com.nimbusds.oauth2.sdk.token.TokenSchemeError;
import java.io.IOException;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import org.jspecify.annotations.Nullable;

public interface TokenFilterHelper {
  String X509_CERTIFICATE_REQUEST_ATTRIBUTE_NAME = "jakarta.servlet.request.X509Certificate";

  @RestrictedApi(explanation = "Internal API", allowedOnPath = ".*/java/net/ltgt/oauth/.*")
  <E extends Exception> void filter(
      String method,
      URI uri,
      List<String> authorizations,
      List<String> dpopProofs,
      @Nullable X509Certificate clientCertificate,
      FilterChain<E> chain)
      throws IOException, E;

  interface FilterChain<E extends Exception> {
    void continueChain() throws IOException, E;

    void continueChain(String authenticationScheme, TokenPrincipal tokenPrincipal)
        throws IOException, E;

    void sendError(List<TokenSchemeError> errors, String message, @Nullable Throwable cause)
        throws IOException, E;

    void sendError(int statusCode, String message, @Nullable Throwable cause) throws IOException, E;
  }
}
