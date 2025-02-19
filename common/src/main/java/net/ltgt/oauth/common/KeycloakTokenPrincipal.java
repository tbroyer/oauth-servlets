package net.ltgt.oauth.common;

import static java.util.Objects.requireNonNull;

import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import java.util.Collection;
import java.util.Optional;

/**
 * A {@link TokenPrincipal} that extracts Keycloak <i>realm</i> roles from the token information.
 */
public class KeycloakTokenPrincipal implements TokenPrincipal {
  public static final TokenPrincipalProvider PROVIDER = KeycloakTokenPrincipal::new;

  private TokenIntrospectionSuccessResponse tokenInfo;

  public KeycloakTokenPrincipal(TokenIntrospectionSuccessResponse tokenInfo) {
    this.tokenInfo = requireNonNull(tokenInfo);
  }

  @Override
  @SuppressWarnings("unchecked")
  public boolean hasRole(String role) {
    // Look into Keycloak-specific role properties
    return Optional.ofNullable(tokenInfo.getJSONObjectParameter("realm_access"))
        .map(realmAccess -> (Collection<String>) realmAccess.get("roles"))
        .map(roles -> roles.contains(role))
        .orElse(false);
  }

  @Override
  public TokenIntrospectionSuccessResponse getTokenInfo() {
    return tokenInfo;
  }
}
