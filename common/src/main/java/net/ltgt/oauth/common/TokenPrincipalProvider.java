package net.ltgt.oauth.common;

import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import org.jspecify.annotations.Nullable;

/**
 * Called by the {@code TokenFilter} on each request to get a {@link TokenPrincipal}.
 *
 * <p>An instance of this class needs to be registered as a {@code ServletContext} attribute or
 * Jakarta RS {@code Configuration} property under the name {@link #CONTEXT_ATTRIBUTE_NAME}.
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
