package net.ltgt.oauth.rs;

import static java.util.Objects.requireNonNull;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.SecurityContext;
import net.ltgt.oauth.common.TokenPrincipal;

/**
 * Ensures the user {@linkplain net.ltgt.oauth.common.TokenPrincipal#hasScope(String) has a given
 * role}
 *
 * @see HasScope
 * @see HasScopeFeature
 */
@Priority(Priorities.AUTHORIZATION)
public class HasScopeFilter extends AbstractAuthorizationFilter {
  private final String scope;

  public HasScopeFilter(String scope) {
    this.scope = requireNonNull(scope);
  }

  @Override
  protected boolean isAuthorized(SecurityContext securityContext) {
    if (securityContext.getUserPrincipal() instanceof TokenPrincipal tokenPrincipal) {
      return tokenPrincipal.hasScope(scope);
    } else {
      return false;
    }
  }

  @Override
  protected Response createForbiddenResponse(ContainerRequestContext requestContext) {
    return createErrorResponse(
        requestContext, BearerTokenError.INSUFFICIENT_SCOPE.setScope(new Scope(scope)));
  }
}
