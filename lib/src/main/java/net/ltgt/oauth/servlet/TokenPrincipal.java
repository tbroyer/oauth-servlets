package net.ltgt.oauth.servlet;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import java.security.Principal;

/** An authenticated user. */
public interface TokenPrincipal extends Principal {
  /**
   * Returns the user's name.
   *
   * <p>The default implementation returns the <i>subject</i> from the token information in {@link
   * #getTokenInfo()}.
   */
  @Override
  default String getName() {
    return getTokenInfo().getSubject().getValue();
  }

  /**
   * Returns whether the user has a given role.
   *
   * @see HasRoleFilter
   * @see jakarta.servlet.http.HttpServletRequest#isUserInRole
   */
  boolean hasRole(String role);

  /**
   * Returns whether the token has a given scope value.
   *
   * <p>The default implementation is equivalent to {@code
   * getTokenInfo().getScope().contains(scope)}.
   *
   * @see HasScopeFilter
   */
  default boolean hasScope(Scope.Value scope) {
    return getTokenInfo().getScope().contains(scope);
  }

  /**
   * Returns whether the token has a given scope value.
   *
   * <p>The default implementation is equivalent to {@code
   * getTokenInfo().getScope().contains(scope)}.
   *
   * @see HasScopeFilter
   */
  default boolean hasScope(String scope) {
    return getTokenInfo().getScope().contains(scope);
  }

  TokenIntrospectionSuccessResponse getTokenInfo();
}
