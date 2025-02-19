package net.ltgt.oauth.common;

import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import java.io.IOException;
import java.security.Principal;
import java.util.concurrent.CompletionException;
import org.jspecify.annotations.Nullable;

public abstract class TokenFilterHelper<E extends Exception> {
  private final TokenIntrospector tokenIntrospector;
  private final TokenPrincipalProvider tokenPrincipalProvider;

  protected TokenFilterHelper(
      TokenIntrospector tokenIntrospector, TokenPrincipalProvider tokenPrincipalProvider) {
    this.tokenIntrospector = tokenIntrospector;
    this.tokenPrincipalProvider = tokenPrincipalProvider;
  }

  public void filter(@Nullable Principal principal, @Nullable String authorization)
      throws IOException, E {
    if (principal != null) {
      continueChain(null);
      return;
    }
    if (authorization == null
        || !authorization.regionMatches(true, 0, "bearer", 0, 6)
        || (authorization.length() != 6 && authorization.charAt(6) != ' ')) {
      continueChain(null);
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
        sendError(
            ((BearerTokenError) e.getErrorObject()), "Error parsing the Authorization header", e);
        return;
      }
    }
    if (token == null) {
      continueChain(null);
      return;
    }
    TokenIntrospectionSuccessResponse introspectionResponse;
    try {
      introspectionResponse = tokenIntrospector.introspect(token);
    } catch (CompletionException e) {
      sendError(HTTPResponse.SC_SERVER_ERROR, "Error introspecting token", e.getCause());
      return;
    }
    if (introspectionResponse == null) {
      sendError(BearerTokenError.INVALID_TOKEN, "Invalid token", null);
      return;
    }
    var tokenPrincipal = tokenPrincipalProvider.getTokenPrincipal(introspectionResponse);
    continueChain(tokenPrincipal);
  }

  protected abstract void continueChain(@Nullable TokenPrincipal tokenPrincipal)
      throws IOException, E;

  protected abstract void sendError(
      BearerTokenError error, String message, @Nullable Throwable cause) throws IOException, E;

  protected abstract void sendError(int statusCode, String message, @Nullable Throwable cause)
      throws IOException, E;
}
