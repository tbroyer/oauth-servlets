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
