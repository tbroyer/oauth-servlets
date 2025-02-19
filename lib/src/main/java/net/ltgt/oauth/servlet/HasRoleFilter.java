package net.ltgt.oauth.servlet;

import static java.util.Objects.requireNonNull;

import com.google.errorprone.annotations.OverridingMethodsMustInvokeSuper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import net.ltgt.oauth.common.TokenPrincipal;

/**
 * Ensures the user {@linkplain TokenPrincipal#hasRole has a given role}.
 *
 * <p>This filter should be installed <i>after</i> the {@link TokenFilter} as it relies on {@link
 * HttpServletRequest#getUserPrincipal()}.
 */
public class HasRoleFilter extends AbstractAuthorizationFilter {
  /** Name of the init parameter used to configure the expected user role. */
  public static final String ROLE = "role";

  private String role;

  public HasRoleFilter() {}

  /**
   * Constructs a filter that checks for the given role.
   *
   * <p>When this constructor is used, the {@link #ROLE} init parameter won't be read.
   */
  public HasRoleFilter(String role) {
    this.role = requireNonNull(role);
  }

  @OverridingMethodsMustInvokeSuper
  @Override
  public void init() throws ServletException {
    if (role == null) {
      role = requireNonNull(getInitParameter(ROLE));
    }
  }

  @Override
  protected boolean isAuthorized(HttpServletRequest req) {
    if (req.getUserPrincipal() instanceof TokenPrincipal tokenPrincipal) {
      return tokenPrincipal.hasRole(role);
    } else {
      return false;
    }
  }
}
