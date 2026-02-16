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
