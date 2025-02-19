package net.ltgt.oauth.common.functional;

import static com.google.common.truth.Truth.assertThat;
import static com.google.common.truth.TruthJUnit.assume;
import static java.util.Objects.requireNonNull;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.oauth2.sdk.as.ReadOnlyAuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import net.ltgt.oauth.common.TokenIntrospector;
import net.ltgt.oauth.common.fixtures.BearerTokenExtension;
import net.ltgt.oauth.common.fixtures.Helpers;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class TokenIntrospectorTest {

  private static ReadOnlyAuthorizationServerMetadata authorizationServerMetadata;
  private static ClientSecretBasic clientAuthentication;

  @RegisterExtension public BearerTokenExtension client = new BearerTokenExtension();

  private TokenIntrospector tokenIntrospector;

  @BeforeAll
  public static void setUpOnce() {
    authorizationServerMetadata = Helpers.loadAuthorizationServerMetadata();
    clientAuthentication =
        new ClientSecretBasic(
            new ClientID(requireNonNull(System.getProperty("test.api.clientId"))),
            new Secret(requireNonNull(System.getProperty("test.api.clientSecret"))));
  }

  @BeforeEach
  public void setUp() {
    tokenIntrospector =
        new TokenIntrospector(
            authorizationServerMetadata, clientAuthentication, Caffeine.newBuilder().recordStats());
  }

  @Test
  public void validToken() {
    var response = tokenIntrospector.introspect(client.get());
    assertThat(response).isNotNull();
    assertThat(requireNonNull(response).isActive()).isTrue();
    assertThat(tokenIntrospector.getCacheStats().loadSuccessCount()).isEqualTo(1L);
  }

  @Test
  public void invalidToken() {
    var response = tokenIntrospector.introspect(new BearerAccessToken("invalid"));
    assertThat(response).isNull();
    assertThat(tokenIntrospector.getCacheStats().loadSuccessCount()).isEqualTo(1L);
  }

  @Test
  public void revokedButCached() throws Exception {
    var token = client.get();
    var response = tokenIntrospector.introspect(token);
    assume().that(response).isNotNull();
    assume().that(requireNonNull(response).isActive()).isTrue();
    assume().that(tokenIntrospector.getCacheStats().loadSuccessCount()).isEqualTo(1L);

    client.revoke(token);

    response = tokenIntrospector.introspect(token);
    assertThat(response).isNotNull();
    assertThat(requireNonNull(response).isActive()).isTrue();
    assertThat(tokenIntrospector.getCacheStats().loadSuccessCount()).isEqualTo(1L);

    tokenIntrospector.invalidate(token);

    response = tokenIntrospector.introspect(token);
    assertThat(response).isNull();
    assertThat(tokenIntrospector.getCacheStats().loadSuccessCount()).isEqualTo(2L);
  }
}
