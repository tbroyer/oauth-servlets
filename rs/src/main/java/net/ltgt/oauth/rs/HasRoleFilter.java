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
