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

import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import org.jspecify.annotations.Nullable;

/**
 * Called by the {@code TokenFilter} on each request to get a {@link TokenPrincipal}.
 *
 * <p>An instance of this class needs to be registered as a {@code ServletContext} attribute or
 * JAX-RS {@code Configuration} property under the name {@link #CONTEXT_ATTRIBUTE_NAME}.
 *
 * <p>The {@link CachedTokenPrincipalProvider} subclass can be used to cache the values when they're
 * somewhat costly to create (for instance because they need to load data from a database).
 *
 * @see CachedTokenPrincipalProvider
 */
@FunctionalInterface
public interface TokenPrincipalProvider {
  String CONTEXT_ATTRIBUTE_NAME = TokenPrincipalProvider.class.getName();

  /**
   * Returns a {@link TokenPrincipal} for the given introspection response.
   *
   * <p>If it returns {@code null} (for example if the token doesn't match any known local
   * <i>user</i>), then the {@code TokenFilter} will let the request in as if no token had been
   * provided (i.e. without a principal).
   *
   * <p>The introspection response is guaranteed to be {@linkplain
   * TokenIntrospectionSuccessResponse#isActive() active} and should represent a token that is still
   * valid at the time of the call.
   */
  @Nullable TokenPrincipal getTokenPrincipal(
      TokenIntrospectionSuccessResponse introspectionResponse);
}
