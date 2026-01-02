package net.ltgt.oauth.common;

import com.google.errorprone.annotations.RestrictedApi;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.oauth2.sdk.token.TokenSchemeError;
import java.util.List;

public class TokenErrorHelper {
  public static final String REQUEST_ATTRIBUTE_NAME = TokenErrorHelper.class.getName();

  private final TokenFilterHelper tokenFilterHelper;

  @RestrictedApi(explanation = "Internal API", allowedOnPath = ".*/java/net/ltgt/oauth/.*")
  public TokenErrorHelper(TokenFilterHelper tokenFilterHelper) {
    this.tokenFilterHelper = tokenFilterHelper;
  }

  @RestrictedApi(explanation = "Internal API", allowedOnPath = ".*/java/net/ltgt/oauth/.*")
  public List<TokenSchemeError> getUnauthorizedErrors() {
    return tokenFilterHelper.getUnauthorizedErrors();
  }

  @RestrictedApi(explanation = "Internal API", allowedOnPath = ".*/java/net/ltgt/oauth/.*")
  public List<TokenSchemeError> adaptError(String authenticationScheme, BearerTokenError error) {
    return tokenFilterHelper.adaptError(authenticationScheme, error);
  }
}
