/*
 * Copyright © 2026 Thomas Broyer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.ltgt.oauth.servlet;

import static java.util.Objects.requireNonNull;

import com.google.errorprone.annotations.OverridingMethodsMustInvokeSuper;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import net.ltgt.oauth.common.TokenPrincipal;

/**
 * Ensures the token {@linkplain TokenPrincipal#hasScope(Scope.Value) has a given scope value}.
 *
 * <p>This filter should be installed <i>after</i> the {@link TokenFilter} as it relies on {@link
 * HttpServletRequest#getUserPrincipal()}.
 */
public class HasScopeFilter extends AbstractAuthorizationFilter {
  public static final String SCOPE = "scope";

  private Scope.Value scope;

  public HasScopeFilter() {}

  /**
   * Constructs a filter that checks for the given scope value.
   *
   * <p>When this constructor is used, the {@link #SCOPE} init parameter won't be read.
   */
  public HasScopeFilter(String scope) {
    this(new Scope.Value(scope));
  }

  /**
   * Constructs a filter that checks for the given scope value.
   *
   * <p>When this constructor is used, the {@link #SCOPE} init parameter won't be read.
   */
  public HasScopeFilter(Scope.Value scope) {
    this.scope = requireNonNull(scope);
  }

  @OverridingMethodsMustInvokeSuper
  @Override
  public void init() throws ServletException {
    if (scope == null) {
      scope = new Scope.Value(getInitParameter(SCOPE));
    }
  }

  @Override
  protected boolean isAuthorized(HttpServletRequest req) {
    if (req.getUserPrincipal() instanceof TokenPrincipal tokenPrincipal) {
      return tokenPrincipal.hasScope(scope);
    } else {
      return false;
    }
  }

  @Override
  protected void sendForbidden(HttpServletRequest req, HttpServletResponse res)
      throws IOException, ServletException {
    sendError(req, res, BearerTokenError.INSUFFICIENT_SCOPE.setScope(new Scope(scope)));
  }
}
