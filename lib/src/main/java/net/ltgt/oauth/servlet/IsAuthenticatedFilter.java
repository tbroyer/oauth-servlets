package net.ltgt.oauth.servlet;

import jakarta.servlet.http.HttpServletRequest;
import net.ltgt.oauth.common.TokenPrincipal;

/** Ensures the user {@linkplain HttpServletRequest#getUserPrincipal is authenticated}. */
public class IsAuthenticatedFilter extends AbstractAuthorizationFilter {
  @Override
  protected boolean isAuthorized(HttpServletRequest req) {
    return req.getUserPrincipal() instanceof TokenPrincipal;
  }
}
