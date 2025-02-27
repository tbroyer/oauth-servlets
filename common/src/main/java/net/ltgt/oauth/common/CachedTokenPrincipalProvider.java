package net.ltgt.oauth.common;

import static java.util.Objects.requireNonNull;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.CacheLoader;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.github.benmanes.caffeine.cache.stats.CacheStats;
import com.google.errorprone.annotations.ForOverride;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import java.util.Optional;
import org.jspecify.annotations.Nullable;

/**
 * Base class for {@link TokenPrincipal} providers whose values should be cached because they're
 * somewhat costly to create (for instance because they need to load data from a database).
 *
 * <p>The {@link #newInstance} static factories can be used to wrap an existing {@link
 * TokenPrincipalProvider} to cache its values.
 *
 * <p>The cache uses {@link Optional} values to cache {@code null} values returned by {@link #load}
 * or the wrapped {@link TokenPrincipalProvider}.
 */
public abstract class CachedTokenPrincipalProvider implements TokenPrincipalProvider {
  private final LoadingCache<TokenIntrospectionSuccessResponse, Optional<TokenPrincipal>> cache;

  /**
   * Wraps the given provider to cache its provided values, using the {@linkplain
   * TokenIntrospector#DEFAULT_MAX_CLOCK_SKEW_SECONDS default max clock skew}.
   *
   * @throws IllegalArgumentException if the given provider is already a {@link
   *     CachedTokenPrincipalProvider}.
   */
  public static CachedTokenPrincipalProvider newInstance(
      TokenPrincipalProvider tokenPrincipalProvider,
      Caffeine<? super TokenIntrospectionSuccessResponse, ? super Optional<TokenPrincipal>>
          cacheBuilder) {
    checkNotAlreadyCached(tokenPrincipalProvider);
    return new CachedTokenPrincipalProvider.Delegating(
        requireNonNull(tokenPrincipalProvider), cacheBuilder);
  }

  /**
   * Wraps the given provider to cache its provided values, using the given max clock skew.
   *
   * @throws IllegalArgumentException if the given provider is already a {@link
   *     CachedTokenPrincipalProvider}.
   */
  public static CachedTokenPrincipalProvider newInstance(
      TokenPrincipalProvider tokenPrincipalProvider,
      Caffeine<? super TokenIntrospectionSuccessResponse, ? super Optional<TokenPrincipal>>
          cacheBuilder,
      int maxClockSkewSeconds) {
    checkNotAlreadyCached(tokenPrincipalProvider);
    return new CachedTokenPrincipalProvider.Delegating(
        requireNonNull(tokenPrincipalProvider), cacheBuilder, maxClockSkewSeconds);
  }

  private static void checkNotAlreadyCached(TokenPrincipalProvider tokenPrincipalProvider) {
    if (tokenPrincipalProvider instanceof CachedTokenPrincipalProvider) {
      throw new IllegalArgumentException(
          "The wrapped provider is already a "
              + CachedTokenPrincipalProvider.class.getSimpleName());
    }
  }

  /**
   * Creates a cached {@link TokenPrincipal} provider with the given cache builder and the
   * {@linkplain TokenIntrospector#DEFAULT_MAX_CLOCK_SKEW_SECONDS default max clock skew}.
   */
  protected CachedTokenPrincipalProvider(
      Caffeine<? super TokenIntrospectionSuccessResponse, ? super Optional<TokenPrincipal>>
          cacheBuilder) {
    this(cacheBuilder, TokenIntrospector.DEFAULT_MAX_CLOCK_SKEW_SECONDS);
  }

  /**
   * Creates a cached {@link TokenPrincipal} provider with the given cache builder and max clock
   * skew.
   */
  protected CachedTokenPrincipalProvider(
      Caffeine<? super TokenIntrospectionSuccessResponse, ? super Optional<TokenPrincipal>>
          cacheBuilder,
      int maxClockSkewSeconds) {
    this.cache =
        cacheBuilder.build(
            new CacheLoader<>() {
              @Override
              public Optional<TokenPrincipal> load(TokenIntrospectionSuccessResponse key) {
                return Optional.ofNullable(CachedTokenPrincipalProvider.this.load(key));
              }

              @Override
              public Optional<TokenPrincipal> reload(
                  TokenIntrospectionSuccessResponse key, Optional<TokenPrincipal> oldValue) {
                if (oldValue.isEmpty()
                    || !TokenIntrospector.isValidToken(key, maxClockSkewSeconds)) {
                  return oldValue;
                }
                return load(key);
              }
            });
  }

  /**
   * Returns a current snapshot of the cache's cumulative statistics.
   *
   * @see Cache#stats()
   */
  public CacheStats getCacheStats() {
    return cache.stats();
  }

  /**
   * Discards any cached introspection response for the given token.
   *
   * @see Cache#invalidate
   */
  public void invalidate(TokenIntrospectionSuccessResponse token) {
    cache.invalidate(token);
  }

  /**
   * Discards any cached introspection response for the given tokens.
   *
   * @see Cache#invalidateAll(Iterable)
   */
  public void invalidateAll(Iterable<? extends TokenIntrospectionSuccessResponse> tokens) {
    cache.invalidateAll(tokens);
  }

  /**
   * Discards all entries in the cache.
   *
   * @see Cache#invalidateAll()
   */
  public void invalidateAll() {
    cache.invalidateAll();
  }

  /**
   * Performs any pending maintenance operations needed by the cache.
   *
   * @see Cache#cleanUp()
   */
  public void cleanUp() {
    cache.cleanUp();
  }

  /**
   * Returns a {@link TokenPrincipal} for the given introspection response.
   *
   * <p>The introspection response is guaranteed to be {@linkplain
   * TokenIntrospectionSuccessResponse#isActive() active} and should represent a token that is still
   * valid at the time of the call.
   */
  @ForOverride
  protected abstract @Nullable TokenPrincipal load(
      TokenIntrospectionSuccessResponse introspectionResponse);

  @Override
  public final @Nullable TokenPrincipal getTokenPrincipal(
      TokenIntrospectionSuccessResponse introspectionResponse) {
    if (!introspectionResponse.isActive()) {
      throw new IllegalArgumentException();
    }
    return cache.get(introspectionResponse).orElse(null);
  }

  private static class Delegating extends CachedTokenPrincipalProvider {

    private final TokenPrincipalProvider tokenPrincipalProvider;

    Delegating(
        TokenPrincipalProvider tokenPrincipalProvider,
        Caffeine<? super TokenIntrospectionSuccessResponse, ? super Optional<TokenPrincipal>>
            cacheBuilder) {
      super(cacheBuilder);
      this.tokenPrincipalProvider = tokenPrincipalProvider;
    }

    Delegating(
        TokenPrincipalProvider tokenPrincipalProvider,
        Caffeine<? super TokenIntrospectionSuccessResponse, ? super Optional<TokenPrincipal>>
            cacheBuilder,
        int maxClockSkewSeconds) {
      super(cacheBuilder, maxClockSkewSeconds);
      this.tokenPrincipalProvider = tokenPrincipalProvider;
    }

    @Override
    protected @Nullable TokenPrincipal load(
        TokenIntrospectionSuccessResponse introspectionResponse) {
      return tokenPrincipalProvider.getTokenPrincipal(introspectionResponse);
    }
  }
}
