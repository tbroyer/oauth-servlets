package net.ltgt.oauth.servlet;

import static java.util.Objects.requireNonNull;

import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;

/** A simple {@link TokenPrincipal} implementation with no role at all. */
public class SimpleTokenPrincipal implements TokenPrincipal {
  public static final TokenPrincipalProvider PROVIDER = SimpleTokenPrincipal::new;

  private TokenIntrospectionSuccessResponse tokenInfo;

  public SimpleTokenPrincipal(TokenIntrospectionSuccessResponse tokenInfo) {
    this.tokenInfo = requireNonNull(tokenInfo);
  }

  @Override
  public boolean hasRole(String role) {
    return false;
  }

  @Override
  public TokenIntrospectionSuccessResponse getTokenInfo() {
    return tokenInfo;
  }
}
