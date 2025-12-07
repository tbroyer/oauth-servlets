package net.ltgt.oauth.common;

import static java.util.Objects.requireNonNull;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.CacheLoader;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import com.github.benmanes.caffeine.cache.stats.CacheStats;
import com.google.errorprone.annotations.ForOverride;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.util.DateUtils;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Request;
import com.nimbusds.oauth2.sdk.TokenIntrospectionRequest;
import com.nimbusds.oauth2.sdk.TokenIntrospectionResponse;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.as.ReadOnlyAuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.http.HTTPRequestSender;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import java.io.IOException;
import java.util.Date;
import java.util.List;
import java.util.Map;
import org.jspecify.annotations.Nullable;

/**
 * Introspects {@linkplain BearerAccessToken bearer tokens} and keep introspection responses in a
 * cache to lower the pressure on the Authorization Server.
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc7662.html">OAuth 2.0 Token Introspection</a>
 */
public class TokenIntrospector {
  public static final String CONTEXT_ATTRIBUTE_NAME = TokenIntrospector.class.getName();

  public static final int DEFAULT_MAX_CLOCK_SKEW_SECONDS =
      DefaultJWTClaimsVerifier.DEFAULT_MAX_CLOCK_SKEW_SECONDS;

  private static ClientAuthenticationSupplier supplier(ClientAuthentication clientAuthentication) {
    requireNonNull(clientAuthentication);
    return () -> clientAuthentication;
  }

  private final ReadOnlyAuthorizationServerMetadata authorizationServerMetadata;
  private final ClientAuthenticationSupplier clientAuthenticationSupplier;
  private final LoadingCache<BearerAccessToken, @Nullable TokenIntrospectionSuccessResponse> cache;
  private final @Nullable HTTPRequestSender httpRequestSender;
  private final int maxClockSkewSeconds;

  public TokenIntrospector(
      ReadOnlyAuthorizationServerMetadata authorizationServerMetadata,
      ClientAuthentication clientAuthentication,
      Caffeine<? super BearerAccessToken, ? super TokenIntrospectionSuccessResponse> cacheBuilder) {
    this(authorizationServerMetadata, supplier(clientAuthentication), cacheBuilder);
  }

  public TokenIntrospector(
      ReadOnlyAuthorizationServerMetadata authorizationServerMetadata,
      ClientAuthenticationSupplier clientAuthenticationSupplier,
      Caffeine<? super BearerAccessToken, ? super TokenIntrospectionSuccessResponse> cacheBuilder) {
    this(
        authorizationServerMetadata,
        clientAuthenticationSupplier,
        cacheBuilder,
        null,
        DEFAULT_MAX_CLOCK_SKEW_SECONDS);
  }

  public TokenIntrospector(
      ReadOnlyAuthorizationServerMetadata authorizationServerMetadata,
      ClientAuthentication clientAuthentication,
      Caffeine<? super BearerAccessToken, ? super TokenIntrospectionSuccessResponse> cacheBuilder,
      @Nullable HTTPRequestSender httpRequestSender) {
    this(
        authorizationServerMetadata,
        supplier(clientAuthentication),
        cacheBuilder,
        httpRequestSender);
  }

  public TokenIntrospector(
      ReadOnlyAuthorizationServerMetadata authorizationServerMetadata,
      ClientAuthenticationSupplier clientAuthenticationSupplier,
      Caffeine<? super BearerAccessToken, ? super TokenIntrospectionSuccessResponse> cacheBuilder,
      @Nullable HTTPRequestSender httpRequestSender) {
    this(
        authorizationServerMetadata,
        clientAuthenticationSupplier,
        cacheBuilder,
        httpRequestSender,
        DEFAULT_MAX_CLOCK_SKEW_SECONDS);
  }

  public TokenIntrospector(
      ReadOnlyAuthorizationServerMetadata authorizationServerMetadata,
      ClientAuthentication clientAuthentication,
      Caffeine<? super BearerAccessToken, ? super TokenIntrospectionSuccessResponse> cacheBuilder,
      int maxClockSkewSeconds) {
    this(
        authorizationServerMetadata,
        supplier(clientAuthentication),
        cacheBuilder,
        maxClockSkewSeconds);
  }

  public TokenIntrospector(
      ReadOnlyAuthorizationServerMetadata authorizationServerMetadata,
      ClientAuthenticationSupplier clientAuthenticationSupplier,
      Caffeine<? super BearerAccessToken, ? super TokenIntrospectionSuccessResponse> cacheBuilder,
      int maxClockSkewSeconds) {
    this(
        authorizationServerMetadata,
        clientAuthenticationSupplier,
        cacheBuilder,
        null,
        maxClockSkewSeconds);
  }

  public TokenIntrospector(
      ReadOnlyAuthorizationServerMetadata authorizationServerMetadata,
      ClientAuthentication clientAuthentication,
      Caffeine<? super BearerAccessToken, ? super TokenIntrospectionSuccessResponse> cacheBuilder,
      @Nullable HTTPRequestSender httpRequestSender,
      int maxClockSkewSeconds) {
    this(
        authorizationServerMetadata,
        supplier(clientAuthentication),
        cacheBuilder,
        httpRequestSender,
        maxClockSkewSeconds);
  }

  public TokenIntrospector(
      ReadOnlyAuthorizationServerMetadata authorizationServerMetadata,
      ClientAuthenticationSupplier clientAuthenticationSupplier,
      Caffeine<? super BearerAccessToken, ? super TokenIntrospectionSuccessResponse> cacheBuilder,
      @Nullable HTTPRequestSender httpRequestSender,
      int maxClockSkewSeconds) {
    this.authorizationServerMetadata = requireNonNull(authorizationServerMetadata);
    this.clientAuthenticationSupplier = requireNonNull(clientAuthenticationSupplier);
    @SuppressWarnings("NullAway")
    var cache =
        cacheBuilder.<BearerAccessToken, @Nullable TokenIntrospectionSuccessResponse>build(
            new CacheLoader<BearerAccessToken, @Nullable TokenIntrospectionSuccessResponse>() {
              @Override
              public TokenIntrospectionSuccessResponse load(BearerAccessToken key)
                  throws Exception {
                return doIntrospect(key);
              }

              @Override
              public TokenIntrospectionSuccessResponse reload(
                  BearerAccessToken key, TokenIntrospectionSuccessResponse oldValue)
                  throws Exception {
                if (!isValidToken(oldValue)) {
                  return oldValue;
                }
                return load(key);
              }
            });
    this.cache = cache;
    this.httpRequestSender = httpRequestSender;
    this.maxClockSkewSeconds = maxClockSkewSeconds;
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
  public void invalidate(BearerAccessToken token) {
    cache.invalidate(token);
  }

  /**
   * Discards any cached introspection response for the given tokens.
   *
   * @see Cache#invalidateAll(Iterable)
   */
  public void invalidateAll(Iterable<? extends BearerAccessToken> tokens) {
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
   * Returns an introspection response for the given token, making an introspection request or
   * taking the response from the internal cache, or {@code null} if the token is not valid.
   *
   * <p>The returned response is guaranteed to be {@linkplain
   * TokenIntrospectionSuccessResponse#isActive() active} and to represent a valid token at the time
   * of the call.
   */
  public @Nullable TokenIntrospectionSuccessResponse introspect(BearerAccessToken token) {
    var response = cache.get(token);
    if (response == null || !isValidToken(response)) {
      return null;
    }
    return response;
  }

  private boolean isValidToken(TokenIntrospectionSuccessResponse successResponse) {
    return isValidToken(successResponse, maxClockSkewSeconds);
  }

  static boolean isValidToken(
      TokenIntrospectionSuccessResponse successResponse, int maxClockSkewSeconds) {
    if (!successResponse.isActive()) {
      return false;
    }
    @SuppressWarnings("JavaUtilDate")
    var now = new Date();
    var exp = successResponse.getExpirationTime();
    if (exp != null && !DateUtils.isAfter(exp, now, maxClockSkewSeconds)) {
      return false;
    }
    var iat = successResponse.getIssueTime();
    if (iat != null && !DateUtils.isBefore(iat, now, maxClockSkewSeconds)) {
      return false;
    }
    var nbf = successResponse.getNotBeforeTime();
    if (nbf != null && !DateUtils.isBefore(nbf, now, maxClockSkewSeconds)) {
      return false;
    }
    return true;
  }

  private TokenIntrospectionSuccessResponse doIntrospect(BearerAccessToken token)
      throws IOException, ParseException {
    var request =
        new TokenIntrospectionRequest(
            authorizationServerMetadata.getIntrospectionEndpointURI(),
            requireNonNull(clientAuthenticationSupplier.getClientAuthentication()),
            token,
            getTokenIntrospectionRequestCustomParams());
    var response = TokenIntrospectionResponse.parse(send(request));
    if (!response.indicatesSuccess()) {
      var errorObject = response.toErrorResponse().getErrorObject();
      throw new ParseException("OAuth token introspection error: " + errorObject, errorObject);
    }
    return response.toSuccessResponse();
  }

  private HTTPResponse send(Request request) throws IOException {
    if (httpRequestSender != null) {
      return request.toHTTPRequest().send(httpRequestSender);
    } else {
      return request.toHTTPRequest().send();
    }
  }

  /**
   * Returns a map of custom parameters to add to the {@linkplain TokenIntrospectionRequest token
   * introspection request}.
   *
   * <p>The default implementation returns {@code null}.
   */
  @ForOverride
  protected @Nullable Map<String, List<String>> getTokenIntrospectionRequestCustomParams() {
    return null;
  }
}
