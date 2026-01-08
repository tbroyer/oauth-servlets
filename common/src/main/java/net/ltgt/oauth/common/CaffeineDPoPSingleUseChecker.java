package net.ltgt.oauth.common;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import com.github.benmanes.caffeine.cache.stats.CacheStats;
import com.google.errorprone.annotations.ThreadSafe;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPProofUse;
import com.nimbusds.oauth2.sdk.dpop.verifiers.InMemoryDPoPSingleUseChecker;
import com.nimbusds.oauth2.sdk.id.JWTID;
import com.nimbusds.oauth2.sdk.util.singleuse.AlreadyUsedException;
import com.nimbusds.oauth2.sdk.util.singleuse.SingleUseChecker;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;

/**
 * In-memory DPoP proof JWT single use checker. Caches a hash of the checked DPoP JWT "jti" (JWT ID)
 * claims for a given DPoP issuer.
 *
 * <p>Compared to {@link InMemoryDPoPSingleUseChecker}, this implementation based on Caffeine does
 * not use background threads/timers and as such does not need to be {@linkplain
 * InMemoryDPoPSingleUseChecker#shutdown() shutdown}.
 */
@ThreadSafe
public class CaffeineDPoPSingleUseChecker implements SingleUseChecker<DPoPProofUse> {
  private final Cache<String, DPoPProofUse> cache;

  /**
   * Constructs a checker with a default cache configuration.
   *
   * <p>This is equivalent to calling {@linkplain #CaffeineDPoPSingleUseChecker(Caffeine) the other
   * constructor overload} wth {@code Caffeine.newBuilder()} as the argument.
   */
  public CaffeineDPoPSingleUseChecker() {
    this(Caffeine.newBuilder());
  }

  /**
   * Constructs a checker with the given maximum cache size.
   *
   * <p>This is equivalent to calling {@linkplain #CaffeineDPoPSingleUseChecker(Caffeine) the other
   * constructor overload} with {@code Caffeine.newBuilder().maximumSize(maximumCacheSize)} as the
   * argument.
   */
  public CaffeineDPoPSingleUseChecker(long maximumCacheSize) {
    this(Caffeine.newBuilder().maximumSize(maximumCacheSize));
  }

  /**
   * Constructs a checker with the given cache builder.
   *
   * <p>The cache builder must not have any expiration configured, and should not have any key or
   * value references strength configured (i.e. it should use strong key and value references).
   *
   * <p>This constructor is mainly provided to allow {@linkplain Caffeine#recordStats() recording
   * stats}, adding a weigher or listeners, or configuring an executor or scheduler.
   */
  public CaffeineDPoPSingleUseChecker(Caffeine<? super String, ? super DPoPProofUse> cacheBuilder) {
    cache =
        cacheBuilder
            .expireAfter(
                Expiry.<String, DPoPProofUse>creating((k, v) -> Duration.ofSeconds(v.getMaxAge())))
            .build();
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
   * Performs any pending maintenance operations needed by the cache.
   *
   * @see Cache#cleanUp()
   */
  public void cleanUp() {
    cache.cleanUp();
  }

  @Override
  public void markAsUsed(DPoPProofUse dpopProofUse) throws AlreadyUsedException {
    var oldValue = cache.asMap().putIfAbsent(computeKey(dpopProofUse), dpopProofUse);
    if (oldValue != null) {
      throw new AlreadyUsedException("Detected jti replay");
    }
  }

  private String computeKey(DPoPProofUse dpopProofUse) {
    return dpopProofUse.getIssuer() + ":" + computeSHA256(dpopProofUse.getJWTID());
  }

  static Base64URL computeSHA256(final JWTID jti) {
    byte[] hash;
    try {
      MessageDigest md = MessageDigest.getInstance("SHA-256");
      hash = md.digest(jti.getValue().getBytes(StandardCharsets.UTF_8));
    } catch (NoSuchAlgorithmException e) {
      throw new RuntimeException(e.getMessage(), e);
    }

    return Base64URL.encode(hash);
  }
}
