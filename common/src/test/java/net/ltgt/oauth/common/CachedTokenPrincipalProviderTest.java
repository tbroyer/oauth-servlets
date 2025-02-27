package net.ltgt.oauth.common;

import static com.google.common.truth.Truth.assertThat;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

public class CachedTokenPrincipalProviderTest {
  @Test
  public void validToken() {
    var count = new AtomicInteger();
    var sut =
        CachedTokenPrincipalProvider.newInstance(
            introspectionResponse -> {
              count.incrementAndGet();
              return new SimpleTokenPrincipal(introspectionResponse);
            },
            Caffeine.newBuilder().recordStats());

    var introspectionResponse = new TokenIntrospectionSuccessResponse.Builder(true).build();

    // First call
    var tokenPrincipal = sut.getTokenPrincipal(introspectionResponse);
    assertThat(tokenPrincipal).isInstanceOf(SimpleTokenPrincipal.class);
    assertThat(count.get()).isEqualTo(1);
    var cacheStats = sut.getCacheStats();
    assertThat(cacheStats.requestCount()).isEqualTo(1L);
    assertThat(cacheStats.hitCount()).isEqualTo(0L);
    assertThat(cacheStats.missCount()).isEqualTo(1L);
    assertThat(cacheStats.loadSuccessCount()).isEqualTo(1L);

    // Second call
    var tokenPrincipal2 = sut.getTokenPrincipal(introspectionResponse);
    assertThat(tokenPrincipal2).isSameInstanceAs(tokenPrincipal);
    assertThat(count.get()).isEqualTo(1);
    var cacheStats2 = sut.getCacheStats();
    assertThat(cacheStats2.requestCount()).isEqualTo(2L);
    assertThat(cacheStats2.hitCount()).isEqualTo(1L);
    assertThat(cacheStats2.missCount()).isEqualTo(1L);
    assertThat(cacheStats2.loadSuccessCount()).isEqualTo(1L);
  }

  @Test
  public void negativeCache() {
    var count = new AtomicInteger();
    var sut =
        CachedTokenPrincipalProvider.newInstance(
            introspectionResponse -> {
              count.incrementAndGet();
              return null;
            },
            Caffeine.newBuilder().recordStats());

    var introspectionResponse = new TokenIntrospectionSuccessResponse.Builder(true).build();

    // First call
    assertThat(sut.getTokenPrincipal(introspectionResponse)).isNull();
    assertThat(count.get()).isEqualTo(1);
    var cacheStats = sut.getCacheStats();
    assertThat(cacheStats.requestCount()).isEqualTo(1L);
    assertThat(cacheStats.hitCount()).isEqualTo(0L);
    assertThat(cacheStats.missCount()).isEqualTo(1L);
    assertThat(cacheStats.loadSuccessCount()).isEqualTo(1L);

    // Second call
    assertThat(sut.getTokenPrincipal(introspectionResponse)).isNull();
    assertThat(count.get()).isEqualTo(1);
    var cacheStats2 = sut.getCacheStats();
    assertThat(cacheStats2.requestCount()).isEqualTo(2L);
    assertThat(cacheStats2.hitCount()).isEqualTo(1L);
    assertThat(cacheStats2.missCount()).isEqualTo(1L);
    assertThat(cacheStats2.loadSuccessCount()).isEqualTo(1L);
  }
}
