package net.ltgt.oauth.common;

import com.google.errorprone.annotations.RestrictedApi;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.oauth2.sdk.token.TokenSchemeError;
import com.nimbusds.openid.connect.sdk.Nonce;
import java.io.IOException;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import org.jspecify.annotations.Nullable;

/** Internal interface used by {@code TokenFilter}. */
public interface TokenFilterHelper {
  String X509_CERTIFICATE_REQUEST_ATTRIBUTE_NAME = "jakarta.servlet.request.X509Certificate";

  String DPOP_HEADER_NAME = "DPoP";
  String DPOP_NONCE_HEADER_NAME = "DPoP-Nonce";

  @RestrictedApi(explanation = "Internal API", allowedOnPath = ".*/java/net/ltgt/oauth/.*")
  List<TokenSchemeError> getUnauthorizedErrors();

  @RestrictedApi(explanation = "Internal API", allowedOnPath = ".*/java/net/ltgt/oauth/.*")
  @Nullable Nonce getDPoPNonce();

  @RestrictedApi(explanation = "Internal API", allowedOnPath = ".*/java/net/ltgt/oauth/.*")
  List<TokenSchemeError> adaptError(String authenticationScheme, BearerTokenError error);

  @RestrictedApi(explanation = "Internal API", allowedOnPath = ".*/java/net/ltgt/oauth/.*")
  <E extends Exception> void filter(
      String method,
      URI uri,
      List<String> authorizations,
      List<String> dpopProofs,
      @Nullable X509Certificate clientCertificate,
      FilterChain<E> chain)
      throws IOException, E;

  /** Internal interface used by {@code TokenFilter}. */
  interface FilterChain<E extends Exception> {
    void continueChain(@Nullable Nonce dpopNonce) throws IOException, E;

    void continueChain(
        String authenticationScheme, TokenPrincipal tokenPrincipal, @Nullable Nonce dpopNonce)
        throws IOException, E;

    void sendError(
        List<TokenSchemeError> errors,
        @Nullable Nonce dpopNonce,
        String message,
        @Nullable Throwable cause)
        throws IOException, E;

    void sendError(int statusCode, String message, @Nullable Throwable cause) throws IOException, E;
  }
}
