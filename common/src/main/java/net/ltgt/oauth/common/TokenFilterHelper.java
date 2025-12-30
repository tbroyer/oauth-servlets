package net.ltgt.oauth.common;

import static java.util.Objects.requireNonNull;

import com.google.errorprone.annotations.RestrictedApi;
import com.nimbusds.jose.util.X509CertUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.oauth2.sdk.token.TokenSchemeError;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.CompletionException;
import org.jspecify.annotations.Nullable;

public class TokenFilterHelper {
  public static final String X509_CERTIFICATE_REQUEST_ATTRIBUTE_NAME =
      "jakarta.servlet.request.X509Certificate";

  private final TokenIntrospector tokenIntrospector;
  private final TokenPrincipalProvider tokenPrincipalProvider;

  @RestrictedApi(explanation = "Internal API", allowedOnPath = ".*/java/net/ltgt/oauth/.*")
  public TokenFilterHelper(
      TokenIntrospector tokenIntrospector, TokenPrincipalProvider tokenPrincipalProvider) {
    this.tokenIntrospector = requireNonNull(tokenIntrospector);
    this.tokenPrincipalProvider = requireNonNull(tokenPrincipalProvider);
  }

  public <E extends Exception> void filter(
      @Nullable String authorization,
      @Nullable X509Certificate clientCertificate,
      FilterChain<E> chain)
      throws IOException, E {
    if (authorization == null
        || !authorization.regionMatches(true, 0, "bearer", 0, 6)
        || (authorization.length() != 6 && authorization.charAt(6) != ' ')) {
      chain.continueChain();
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
            "Error parsing the Authorization header",
            e);
        return;
      }
    }
    if (token == null) {
      chain.continueChain();
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
      chain.sendError(List.of(BearerTokenError.INVALID_TOKEN), "Invalid token", null);
      return;
    }
    var x509CertificateConfirmation = introspectionResponse.getX509CertificateConfirmation();
    if (x509CertificateConfirmation != null) {
      if (clientCertificate == null) {
        chain.sendError(
            List.of(BearerTokenError.INVALID_TOKEN), "No client certificate presented", null);
        return;
      }
      if (!x509CertificateConfirmation
          .getValue()
          .equals(X509CertUtils.computeSHA256Thumbprint(clientCertificate))) {
        chain.sendError(
            List.of(BearerTokenError.INVALID_TOKEN),
            "Presented client certificate doesn't match sender-constrained access token",
            null);
        return;
      }
    }
    var tokenPrincipal = tokenPrincipalProvider.getTokenPrincipal(introspectionResponse);
    if (tokenPrincipal != null) {
      chain.continueChain(AccessTokenType.BEARER.getValue(), tokenPrincipal);
    } else {
      chain.continueChain();
    }
  }

  public interface FilterChain<E extends Exception> {
    void continueChain() throws IOException, E;

    void continueChain(String authenticationScheme, TokenPrincipal tokenPrincipal)
        throws IOException, E;

    void sendError(List<TokenSchemeError> errors, String message, @Nullable Throwable cause)
        throws IOException, E;

    void sendError(int statusCode, String message, @Nullable Throwable cause) throws IOException, E;
  }
}
