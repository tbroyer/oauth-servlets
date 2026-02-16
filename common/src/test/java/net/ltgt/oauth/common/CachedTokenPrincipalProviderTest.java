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
