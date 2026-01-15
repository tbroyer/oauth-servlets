package net.ltgt.oauth.common.functional;

import static com.google.common.truth.Truth.assertThat;
import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.fail;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.as.ReadOnlyAuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.oauth2.sdk.token.TokenSchemeError;
import com.nimbusds.openid.connect.sdk.Nonce;
import java.net.URI;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;
import net.ltgt.oauth.common.BearerTokenFilterHelper;
import net.ltgt.oauth.common.KeycloakTokenPrincipal;
import net.ltgt.oauth.common.TokenFilterHelper;
import net.ltgt.oauth.common.TokenIntrospector;
import net.ltgt.oauth.common.TokenPrincipal;
import net.ltgt.oauth.common.fixtures.BearerTokenExtension;
import net.ltgt.oauth.common.fixtures.DPoPTokenExtension;
import net.ltgt.oauth.common.fixtures.Helpers;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class BearerTokenFilterHelperTest {

  private static final String REQUEST_METHOD = "GET";
  private static final URI REQUEST_URI = URI.create("http://localhost/api");

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
        BearerTokenFilterHelper.FACTORY.create(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER);

    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of(),
        List.of(),
        null,
        new TokenFilterHelper.FilterChain<Exception>() {
          @Override
          public void continueChain(@Nullable Nonce dpopNonce) {
            called.set(true);
            assertThat(dpopNonce).isNull();
          }

          @Override
          public void continueChain(
              String authenticationScheme,
              TokenPrincipal tokenPrincipal,
              @Nullable Nonce dpopNonce) {
            fail();
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors,
              @Nullable Nonce dpopNonce,
              String message,
              @Nullable Throwable cause) {
            fail();
          }

          @Override
          public void sendError(int statusCode, String message, @Nullable Throwable cause) {
            fail();
          }
        });

    assertThat(called.get()).isTrue();
  }

  @Test
  public void badAuthScheme() throws Exception {
    var called = new AtomicBoolean();
    var sut =
        BearerTokenFilterHelper.FACTORY.create(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER);

    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of(clientAuthentication.toHTTPAuthorizationHeader()),
        List.of(),
        null,
        new TokenFilterHelper.FilterChain<Exception>() {
          @Override
          public void continueChain(@Nullable Nonce dpopNonce) {
            called.set(true);
            assertThat(dpopNonce).isNull();
          }

          @Override
          public void continueChain(
              String authenticationScheme,
              TokenPrincipal tokenPrincipal,
              @Nullable Nonce dpopNonce) {
            fail();
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors,
              @Nullable Nonce dpopNonce,
              String message,
              @Nullable Throwable cause) {
            fail();
          }

          @Override
          public void sendError(int statusCode, String message, @Nullable Throwable cause) {
            fail();
          }
        });

    assertThat(called.get()).isTrue();
  }

  @Test
  public void badAuthScheme2() throws Exception {
    var called = new AtomicBoolean();
    var sut =
        BearerTokenFilterHelper.FACTORY.create(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER);

    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of("bearertoken"),
        List.of(),
        null,
        new TokenFilterHelper.FilterChain<Exception>() {
          @Override
          public void continueChain(@Nullable Nonce dpopNonce) {
            called.set(true);
            assertThat(dpopNonce).isNull();
          }

          @Override
          public void continueChain(
              String authenticationScheme,
              TokenPrincipal tokenPrincipal,
              @Nullable Nonce dpopNonce) {
            fail();
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors,
              @Nullable Nonce dpopNonce,
              String message,
              @Nullable Throwable cause) {
            fail();
          }

          @Override
          public void sendError(int statusCode, String message, @Nullable Throwable cause) {
            fail();
          }
        });

    assertThat(called.get()).isTrue();
  }

  @Test
  public void missingToken() throws Exception {
    var called = new AtomicBoolean();
    var sut =
        BearerTokenFilterHelper.FACTORY.create(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER);

    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of("bearer"),
        List.of(),
        null,
        new TokenFilterHelper.FilterChain<Exception>() {
          @Override
          public void continueChain(@Nullable Nonce dpopNonce) {
            fail();
          }

          @Override
          public void continueChain(
              String authenticationScheme,
              TokenPrincipal tokenPrincipal,
              @Nullable Nonce dpopNonce) {
            fail();
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors,
              @Nullable Nonce dpopNonce,
              String message,
              @Nullable Throwable cause) {
            called.set(true);
            assertThat(errors).containsExactly(BearerTokenError.INVALID_REQUEST);
            assertThat(dpopNonce).isNull();
          }

          @Override
          public void sendError(int statusCode, String message, @Nullable Throwable cause) {
            fail();
          }
        });

    assertThat(called.get()).isTrue();
  }

  @Test
  public void missingToken2() throws Exception {
    var called = new AtomicBoolean();
    var sut =
        BearerTokenFilterHelper.FACTORY.create(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER);

    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of("bearer "),
        List.of(),
        null,
        new TokenFilterHelper.FilterChain<Exception>() {
          @Override
          public void continueChain(@Nullable Nonce dpopNonce) {
            fail();
          }

          @Override
          public void continueChain(
              String authenticationScheme,
              TokenPrincipal tokenPrincipal,
              @Nullable Nonce dpopNonce) {
            fail();
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors,
              @Nullable Nonce dpopNonce,
              String message,
              @Nullable Throwable cause) {
            called.set(true);
            assertThat(errors).containsExactly(BearerTokenError.INVALID_REQUEST);
            assertThat(dpopNonce).isNull();
          }

          @Override
          public void sendError(int statusCode, String message, @Nullable Throwable cause) {
            fail();
          }
        });

    assertThat(called.get()).isTrue();
  }

  @Test
  public void invalidToken() throws Exception {
    var called = new AtomicBoolean();
    var sut =
        BearerTokenFilterHelper.FACTORY.create(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER);

    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of("bearer invalid"),
        List.of(),
        null,
        new TokenFilterHelper.FilterChain<Exception>() {
          @Override
          public void continueChain(@Nullable Nonce dpopNonce) {
            fail();
          }

          @Override
          public void continueChain(
              String authenticationScheme,
              TokenPrincipal tokenPrincipal,
              @Nullable Nonce dpopNonce) {
            fail();
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors,
              @Nullable Nonce dpopNonce,
              String message,
              @Nullable Throwable cause) {
            called.set(true);
            assertThat(errors).containsExactly(BearerTokenError.INVALID_TOKEN);
            assertThat(dpopNonce).isNull();
          }

          @Override
          public void sendError(int statusCode, String message, @Nullable Throwable cause) {
            fail();
          }
        });

    assertThat(called.get()).isTrue();
  }

  @Test
  public void validToken() throws Exception {
    var called = new AtomicBoolean();
    var sut =
        BearerTokenFilterHelper.FACTORY.create(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER);

    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of(client.get().toAuthorizationHeader()),
        List.of(),
        null,
        new TokenFilterHelper.FilterChain<Exception>() {
          @Override
          public void continueChain(@Nullable Nonce dpopNonce) {
            fail();
          }

          @Override
          public void continueChain(
              String authenticationScheme,
              TokenPrincipal tokenPrincipal,
              @Nullable Nonce dpopNonce) {
            called.set(true);
            assertThat(authenticationScheme).isEqualTo(AccessTokenType.BEARER.getValue());
            assertThat(tokenPrincipal.getTokenInfo().getUsername())
                .isEqualTo("service-account-app");
            assertThat(dpopNonce).isNull();
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors,
              @Nullable Nonce dpopNonce,
              String message,
              @Nullable Throwable cause) {
            fail();
          }

          @Override
          public void sendError(int statusCode, String message, @Nullable Throwable cause) {
            fail();
          }
        });

    assertThat(called.get()).isTrue();
  }

  @Test
  public void validTokenInSecondAuthorizationHeader() throws Exception {
    var called = new AtomicBoolean();
    var sut =
        BearerTokenFilterHelper.FACTORY.create(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER);

    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of(
            clientAuthentication.toHTTPAuthorizationHeader(), client.get().toAuthorizationHeader()),
        List.of(),
        null,
        new TokenFilterHelper.FilterChain<Exception>() {
          @Override
          public void continueChain(@Nullable Nonce dpopNonce) {
            fail();
          }

          @Override
          public void continueChain(
              String authenticationScheme,
              TokenPrincipal tokenPrincipal,
              @Nullable Nonce dpopNonce) {
            called.set(true);
            assertThat(authenticationScheme).isEqualTo(AccessTokenType.BEARER.getValue());
            assertThat(tokenPrincipal.getTokenInfo().getUsername())
                .isEqualTo("service-account-app");
            assertThat(dpopNonce).isNull();
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors,
              @Nullable Nonce dpopNonce,
              String message,
              @Nullable Throwable cause) {
            fail();
          }

          @Override
          public void sendError(int statusCode, String message, @Nullable Throwable cause) {
            fail();
          }
        });

    assertThat(called.get()).isTrue();
  }

  @Test
  public void revokedButCachedToken() throws Exception {
    var called = new AtomicBoolean();
    var sut =
        BearerTokenFilterHelper.FACTORY.create(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER);
    var chain =
        new TokenFilterHelper.FilterChain<Exception>() {
          @Override
          public void continueChain(@Nullable Nonce dpopNonce) {
            fail();
          }

          @Override
          public void continueChain(
              String authenticationScheme,
              TokenPrincipal tokenPrincipal,
              @Nullable Nonce dpopNonce) {
            called.set(true);
            assertThat(authenticationScheme).isEqualTo(AccessTokenType.BEARER.getValue());
            assertThat(tokenPrincipal.getTokenInfo().getUsername())
                .isEqualTo("service-account-app");
            assertThat(dpopNonce).isNull();
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors,
              @Nullable Nonce dpopNonce,
              String message,
              @Nullable Throwable cause) {
            fail();
          }

          @Override
          public void sendError(int statusCode, String message, @Nullable Throwable cause) {
            fail();
          }
        };

    var token = client.get();
    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of(token.toAuthorizationHeader()),
        List.of(),
        null,
        chain);
    assertThat(called.get()).isTrue();

    client.revoke(token);

    called.set(false);
    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of(token.toAuthorizationHeader()),
        List.of(),
        null,
        chain);

    assertThat(called.get()).isTrue();
  }

  @Test
  public void validTokenNoTokenPrincipal() throws Exception {
    var called = new AtomicBoolean();
    var sut = BearerTokenFilterHelper.FACTORY.create(tokenIntrospector, ignored -> null);

    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of(client.get().toAuthorizationHeader()),
        List.of(),
        null,
        new TokenFilterHelper.FilterChain<Exception>() {
          @Override
          public void continueChain(@Nullable Nonce dpopNonce) {
            called.set(true);
            assertThat(dpopNonce).isNull();
          }

          @Override
          public void continueChain(
              String authenticationScheme,
              TokenPrincipal tokenPrincipal,
              @Nullable Nonce dpopNonce) {
            fail();
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors,
              @Nullable Nonce dpopNonce,
              String message,
              @Nullable Throwable cause) {
            fail();
          }

          @Override
          public void sendError(int statusCode, String message, @Nullable Throwable cause) {
            fail();
          }
        });

    assertThat(called.get()).isTrue();
  }

  @Nested
  class DPoPInterop {
    @RegisterExtension
    public DPoPTokenExtension dpopClient = new DPoPTokenExtension(JWSAlgorithm.ES256);

    @Test
    public void validDPoPTokenUsedAsBearer() throws Exception {
      var called = new AtomicBoolean();
      var sut =
          BearerTokenFilterHelper.FACTORY.create(
              tokenIntrospector, KeycloakTokenPrincipal.PROVIDER);

      sut.filter(
          REQUEST_METHOD,
          REQUEST_URI,
          List.of(new BearerAccessToken(dpopClient.get().getValue()).toAuthorizationHeader()),
          List.of(),
          null,
          new TokenFilterHelper.FilterChain<Exception>() {
            @Override
            public void continueChain(@Nullable Nonce dpopNonce) {
              fail();
            }

            @Override
            public void continueChain(
                String authenticationScheme,
                TokenPrincipal tokenPrincipal,
                @Nullable Nonce dpopNonce) {
              called.set(true);
              assertThat(tokenPrincipal.getTokenInfo().getUsername())
                  .isEqualTo("service-account-app");
              assertThat(dpopNonce).isNull();
            }

            @Override
            public void sendError(
                List<TokenSchemeError> errors,
                @Nullable Nonce dpopNonce,
                String message,
                @Nullable Throwable cause) {
              fail();
            }

            @Override
            public void sendError(int statusCode, String message, @Nullable Throwable cause) {
              fail();
            }
          });
      assertThat(called.get()).isTrue();
    }
  }
}
