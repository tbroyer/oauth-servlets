package net.ltgt.oauth.common;

import com.google.errorprone.annotations.RestrictedApi;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.oauth2.sdk.token.TokenSchemeError;
import com.nimbusds.openid.connect.sdk.Nonce;
import java.util.List;
import org.jspecify.annotations.Nullable;

/** Internal class used by {@code TokenFilter} and {@code AbstractAuthorizationFilter}. */
public class TokenErrorHelper {
  public static final String REQUEST_ATTRIBUTE_NAME = TokenErrorHelper.class.getName();

  public static final String DPOP_NONCE_HEADER_NAME = TokenFilterHelper.DPOP_NONCE_HEADER_NAME;

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
  public @Nullable Nonce getDPoPNonce() {
    return tokenFilterHelper.getDPoPNonce();
  }
  ;

  @RestrictedApi(explanation = "Internal API", allowedOnPath = ".*/java/net/ltgt/oauth/.*")
  public List<TokenSchemeError> adaptError(String authenticationScheme, BearerTokenError error) {
    return tokenFilterHelper.adaptError(authenticationScheme, error);
  }
}
