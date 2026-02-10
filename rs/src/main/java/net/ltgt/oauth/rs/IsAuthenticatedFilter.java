package net.ltgt.oauth.rs;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.core.SecurityContext;
import jakarta.ws.rs.ext.Provider;
import net.ltgt.oauth.common.TokenPrincipal;

/** Ensures the user {@linkplain SecurityContext#getUserPrincipal is authenticated}. */
@IsAuthenticated
@Provider
@Priority(Priorities.AUTHORIZATION)
public class IsAuthenticatedFilter extends AbstractAuthorizationFilter {
  @Override
  protected boolean isAuthorized(SecurityContext securityContext) {
    return securityContext.getUserPrincipal() instanceof TokenPrincipal;
  }
}
