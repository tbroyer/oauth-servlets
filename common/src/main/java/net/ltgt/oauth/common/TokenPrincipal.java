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
package net.ltgt.oauth.common;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import java.security.Principal;

/** An authenticated user. */
public interface TokenPrincipal extends Principal {
  /**
   * Returns the user's name.
   *
   * @implSpec The default implementation returns the <i>subject</i> from the token information in
   *     {@link #getTokenInfo()}.
   */
  @Override
  default String getName() {
    return getTokenInfo().getSubject().getValue();
  }

  /** Returns whether the user has a given role. */
  boolean hasRole(String role);

  /**
   * Returns whether the token has a given scope value.
   *
   * @implSpec The default implementation is equivalent to {@code
   *     getTokenInfo().getScope().contains(scope)}.
   */
  default boolean hasScope(Scope.Value scope) {
    return getTokenInfo().getScope().contains(scope);
  }

  /**
   * Returns whether the token has a given scope value.
   *
   * @implSpec The default implementation is equivalent to {@code
   *     getTokenInfo().getScope().contains(scope)}.
   */
  default boolean hasScope(String scope) {
    return getTokenInfo().getScope().contains(scope);
  }

  TokenIntrospectionSuccessResponse getTokenInfo();
}
