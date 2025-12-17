package net.ltgt.oauth.common;

import com.google.errorprone.annotations.RestrictedApi;

/**
 * Called by {@code TokenFilter} (either at initialization time, or on each request) to create a
 * {@link TokenFilterHelper}.
 *
 * <p>An instance of this class needs to be registered as a {@code ServletContext} attribute or
 * JAX-RS {@code Configuration} property under the name {@link #CONTEXT_ATTRIBUTE_NAME}. If no such
 * instance is configured, {@code TokenFilter} will default to using {@link
 * BearerTokenFilterHelper#FACTORY}.
 *
 * @see BearerTokenFilterHelper#FACTORY
 * @see DPoPTokenFilterHelper.Factory
 */
public interface TokenFilterHelperFactory {
  String CONTEXT_ATTRIBUTE_NAME = TokenFilterHelperFactory.class.getName();

  /**
   * Creates a new {@link TokenFilterHelper} instance with the given token introspector and token
   * principal provider.
   */
  @RestrictedApi(explanation = "Internal API", allowedOnPath = ".*/java/net/ltgt/oauth/.*")
  TokenFilterHelper create(
      TokenIntrospector tokenIntrospector, TokenPrincipalProvider tokenPrincipalProvider);
}
