package net.ltgt.oauth.rs;

import static java.util.Objects.requireNonNull;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.core.SecurityContext;
import net.ltgt.oauth.common.TokenPrincipal;

/**
 * Ensures the user {@linkplain net.ltgt.oauth.common.TokenPrincipal#hasRole has a given role}.
 *
 * @see HasRole
 * @see HasRoleFeature
 */
@Priority(Priorities.AUTHORIZATION)
public class HasRoleFilter extends AbstractAuthorizationFilter {
  private final String role;

  public HasRoleFilter(String role) {
    this.role = requireNonNull(role);
  }

  @Override
  protected boolean isAuthorized(SecurityContext securityContext) {
    if (securityContext.getUserPrincipal() instanceof TokenPrincipal tokenPrincipal) {
      return tokenPrincipal.hasRole(role);
    } else {
      return false;
    }
  }
}
