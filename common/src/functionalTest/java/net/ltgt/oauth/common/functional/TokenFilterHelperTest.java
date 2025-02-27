package net.ltgt.oauth.common.functional;

import static com.google.common.truth.Truth.assertThat;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.fail;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.oauth2.sdk.as.ReadOnlyAuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import java.util.concurrent.atomic.AtomicBoolean;
import net.ltgt.oauth.common.KeycloakTokenPrincipal;
import net.ltgt.oauth.common.TokenFilterHelper;
import net.ltgt.oauth.common.TokenIntrospector;
import net.ltgt.oauth.common.TokenPrincipal;
import net.ltgt.oauth.common.fixtures.BearerTokenExtension;
import net.ltgt.oauth.common.fixtures.Helpers;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class TokenFilterHelperTest {

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
  public void noAuthentication() throws Exception {
    var called = new AtomicBoolean();
    var sut =
        new TokenFilterHelper<>(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER) {
          @Override
          protected void continueChain(@Nullable TokenPrincipal tokenPrincipal) {
            called.set(true);
            assertThat(tokenPrincipal).isNull();
          }

          @Override
          protected void sendError(
              BearerTokenError error, String message, @Nullable Throwable cause) {
            fail();
          }

          @Override
          protected void sendError(int statusCode, String message, @Nullable Throwable cause) {
            fail();
          }
        };

    sut.filter(null, null);
    assertThat(called.get()).isTrue();
  }

  @Test
  public void badAuthScheme() throws Exception {
    var called = new AtomicBoolean();
    var sut =
        new TokenFilterHelper<>(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER) {
          @Override
          protected void continueChain(@Nullable TokenPrincipal tokenPrincipal) {
            called.set(true);
            assertThat(tokenPrincipal).isNull();
          }

          @Override
          protected void sendError(
              BearerTokenError error, String message, @Nullable Throwable cause) {
            fail();
          }

          @Override
          protected void sendError(int statusCode, String message, @Nullable Throwable cause) {
            fail();
          }
        };

    sut.filter(null, clientAuthentication.toHTTPAuthorizationHeader());
    assertThat(called.get()).isTrue();
  }

  @Test
  public void badAuthScheme2() throws Exception {
    var called = new AtomicBoolean();
    var sut =
        new TokenFilterHelper<>(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER) {
          @Override
          protected void continueChain(@Nullable TokenPrincipal tokenPrincipal) {
            called.set(true);
            assertThat(tokenPrincipal).isNull();
          }

          @Override
          protected void sendError(
              BearerTokenError error, String message, @Nullable Throwable cause) {
            fail();
          }

          @Override
          protected void sendError(int statusCode, String message, @Nullable Throwable cause) {
            fail();
          }
        };

    sut.filter(null, "bearertoken");
    assertThat(called.get()).isTrue();
  }

  @Test
  public void missingToken() throws Exception {
    var called = new AtomicBoolean();
    var sut =
        new TokenFilterHelper<>(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER) {
          @Override
          protected void continueChain(@Nullable TokenPrincipal tokenPrincipal) {
            fail();
          }

          @Override
          protected void sendError(
              BearerTokenError error, String message, @Nullable Throwable cause) {
            called.set(true);
            assertThat(error).isEqualTo(BearerTokenError.INVALID_REQUEST);
          }

          @Override
          protected void sendError(int statusCode, String message, @Nullable Throwable cause) {
            fail();
          }
        };

    sut.filter(null, "bearer");
    assertThat(called.get()).isTrue();
  }

  @Test
  public void missingToken2() throws Exception {
    var called = new AtomicBoolean();
    var sut =
        new TokenFilterHelper<>(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER) {
          @Override
          protected void continueChain(@Nullable TokenPrincipal tokenPrincipal) {
            fail();
          }

          @Override
          protected void sendError(
              BearerTokenError error, String message, @Nullable Throwable cause) {
            called.set(true);
            assertThat(error).isEqualTo(BearerTokenError.INVALID_REQUEST);
          }

          @Override
          protected void sendError(int statusCode, String message, @Nullable Throwable cause) {
            fail();
          }
        };

    sut.filter(null, "bearer ");
    assertThat(called.get()).isTrue();
  }

  @Test
  public void invalidToken() throws Exception {
    var called = new AtomicBoolean();
    var sut =
        new TokenFilterHelper<>(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER) {
          @Override
          protected void continueChain(@Nullable TokenPrincipal tokenPrincipal) {
            fail();
          }

          @Override
          protected void sendError(
              BearerTokenError error, String message, @Nullable Throwable cause) {
            called.set(true);
            assertThat(error).isEqualTo(BearerTokenError.INVALID_TOKEN);
          }

          @Override
          protected void sendError(int statusCode, String message, @Nullable Throwable cause) {
            fail();
          }
        };

    sut.filter(null, "bearer invalid");
    assertThat(called.get()).isTrue();
  }

  @Test
  public void validToken() throws Exception {
    var called = new AtomicBoolean();
    var sut =
        new TokenFilterHelper<>(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER) {
          @Override
          protected void continueChain(@Nullable TokenPrincipal tokenPrincipal) {
            called.set(true);
            assertThat(tokenPrincipal).isNotNull();
            assertThat(requireNonNull(tokenPrincipal).getTokenInfo().getUsername())
                .isEqualTo("service-account-app");
          }

          @Override
          protected void sendError(
              BearerTokenError error, String message, @Nullable Throwable cause) {
            fail();
          }

          @Override
          protected void sendError(int statusCode, String message, @Nullable Throwable cause) {
            fail();
          }
        };

    sut.filter(null, client.get().toAuthorizationHeader());
    assertThat(called.get()).isTrue();
  }

  @Test
  public void revokedButCachedToken() throws Exception {
    var called = new AtomicBoolean();
    var sut =
        new TokenFilterHelper<>(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER) {
          @Override
          protected void continueChain(@Nullable TokenPrincipal tokenPrincipal) {
            called.set(true);
            assertThat(tokenPrincipal).isNotNull();
            assertThat(requireNonNull(tokenPrincipal).getTokenInfo().getUsername())
                .isEqualTo("service-account-app");
          }

          @Override
          protected void sendError(
              BearerTokenError error, String message, @Nullable Throwable cause) {
            fail();
          }

          @Override
          protected void sendError(int statusCode, String message, @Nullable Throwable cause) {
            fail();
          }
        };

    var token = client.get();
    sut.filter(null, token.toAuthorizationHeader());
    assertThat(called.get()).isTrue();

    client.revoke(token);

    called.set(false);
    sut.filter(null, token.toAuthorizationHeader());
    assertThat(called.get()).isTrue();
  }

  @Test
  public void validTokenNoTokenPrincipal() throws Exception {
    var called = new AtomicBoolean();
    var sut =
        new TokenFilterHelper<>(tokenIntrospector, ignored -> null) {
          @Override
          protected void continueChain(@Nullable TokenPrincipal tokenPrincipal) {
            called.set(true);
            assertThat(tokenPrincipal).isNull();
          }

          @Override
          protected void sendError(
              BearerTokenError error, String message, @Nullable Throwable cause) {
            fail();
          }

          @Override
          protected void sendError(int statusCode, String message, @Nullable Throwable cause) {
            fail();
          }
        };

    sut.filter(null, client.get().toAuthorizationHeader());
    assertThat(called.get()).isTrue();
  }
}
