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
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.oauth2.sdk.token.DPoPTokenError;
import com.nimbusds.oauth2.sdk.token.TokenSchemeError;
import java.net.URI;
import java.util.List;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;
import net.ltgt.oauth.common.DPoPTokenFilterHelper;
import net.ltgt.oauth.common.KeycloakTokenPrincipal;
import net.ltgt.oauth.common.TokenFilterHelper;
import net.ltgt.oauth.common.TokenFilterHelperFactory;
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

public class DPoPTokenFilterHelperTest {

  private static final String REQUEST_METHOD = "GET";
  private static final URI REQUEST_URI = URI.create("http://localhost/api");
  private static final Set<JWSAlgorithm> ALGS = Set.of(JWSAlgorithm.ES256, JWSAlgorithm.PS256);

  private static ReadOnlyAuthorizationServerMetadata authorizationServerMetadata;
  private static ClientSecretBasic clientAuthentication;
  private static TokenFilterHelperFactory factory = new DPoPTokenFilterHelper.Factory(ALGS, null);

  @RegisterExtension public DPoPTokenExtension client = new DPoPTokenExtension(JWSAlgorithm.ES256);

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
    var sut = factory.create(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER);

    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of(),
        List.of(),
        null,
        new TokenFilterHelper.FilterChain<Exception>() {
          @Override
          public void continueChain() {
            called.set(true);
          }

          @Override
          public void continueChain(String authenticationScheme, TokenPrincipal tokenPrincipal) {
            fail();
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors, String message, @Nullable Throwable cause) {
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
    var sut = factory.create(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER);

    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of(clientAuthentication.toHTTPAuthorizationHeader()),
        List.of(),
        null,
        new TokenFilterHelper.FilterChain<Exception>() {
          @Override
          public void continueChain() {
            called.set(true);
          }

          @Override
          public void continueChain(String authenticationScheme, TokenPrincipal tokenPrincipal) {
            fail();
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors, String message, @Nullable Throwable cause) {
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
    var sut = factory.create(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER);

    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of("dpoptoken"),
        List.of(),
        null,
        new TokenFilterHelper.FilterChain<Exception>() {
          @Override
          public void continueChain() {
            called.set(true);
          }

          @Override
          public void continueChain(String authenticationScheme, TokenPrincipal tokenPrincipal) {
            fail();
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors, String message, @Nullable Throwable cause) {
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
    var sut = factory.create(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER);

    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of("dpop"),
        List.of(),
        null,
        new TokenFilterHelper.FilterChain<Exception>() {
          @Override
          public void continueChain() {
            fail();
          }

          @Override
          public void continueChain(String authenticationScheme, TokenPrincipal tokenPrincipal) {
            fail();
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors, String message, @Nullable Throwable cause) {
            called.set(true);
            assertThat(errors)
                .containsExactly(DPoPTokenError.INVALID_REQUEST.setJWSAlgorithms(ALGS));
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
    var sut = factory.create(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER);

    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of("dpop "),
        List.of(),
        null,
        new TokenFilterHelper.FilterChain<Exception>() {
          @Override
          public void continueChain() {
            fail();
          }

          @Override
          public void continueChain(String authenticationScheme, TokenPrincipal tokenPrincipal) {
            fail();
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors, String message, @Nullable Throwable cause) {
            called.set(true);
            assertThat(errors)
                .containsExactly(DPoPTokenError.INVALID_REQUEST.setJWSAlgorithms(ALGS));
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
    var sut = factory.create(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER);

    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of("dpop invalid"),
        List.of(
            client
                .createDPoPJWT(REQUEST_METHOD, REQUEST_URI, new DPoPAccessToken("invalid"))
                .serialize()),
        null,
        new TokenFilterHelper.FilterChain<Exception>() {
          @Override
          public void continueChain() {
            fail();
          }

          @Override
          public void continueChain(String authenticationScheme, TokenPrincipal tokenPrincipal) {
            fail();
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors, String message, @Nullable Throwable cause) {
            called.set(true);
            assertThat(errors).containsExactly(DPoPTokenError.INVALID_TOKEN.setJWSAlgorithms(ALGS));
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
    var sut = factory.create(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER);

    var token = client.get();
    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of(token.toAuthorizationHeader()),
        List.of(client.createDPoPJWT(REQUEST_METHOD, REQUEST_URI, token).serialize()),
        null,
        new TokenFilterHelper.FilterChain<Exception>() {
          @Override
          public void continueChain() {
            fail();
          }

          @Override
          public void continueChain(String authenticationScheme, TokenPrincipal tokenPrincipal) {
            called.set(true);
            assertThat(authenticationScheme).isEqualTo(AccessTokenType.DPOP.getValue());
            assertThat(tokenPrincipal.getTokenInfo().getUsername())
                .isEqualTo("service-account-app");
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors, String message, @Nullable Throwable cause) {
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
    var sut = factory.create(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER);

    var token = client.get();
    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of(clientAuthentication.toHTTPAuthorizationHeader(), token.toAuthorizationHeader()),
        List.of(client.createDPoPJWT(REQUEST_METHOD, REQUEST_URI, token).serialize()),
        null,
        new TokenFilterHelper.FilterChain<Exception>() {
          @Override
          public void continueChain() {
            fail();
          }

          @Override
          public void continueChain(String authenticationScheme, TokenPrincipal tokenPrincipal) {
            called.set(true);
            assertThat(authenticationScheme).isEqualTo(AccessTokenType.DPOP.getValue());
            assertThat(tokenPrincipal.getTokenInfo().getUsername())
                .isEqualTo("service-account-app");
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors, String message, @Nullable Throwable cause) {
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
  public void invalidDPoPProof() throws Exception {
    var called = new AtomicBoolean();
    var sut = factory.create(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER);

    var token = client.get();
    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of(token.toAuthorizationHeader()),
        List.of(client.createDPoPJWT("POST", REQUEST_URI, token).serialize()),
        null,
        new TokenFilterHelper.FilterChain<Exception>() {
          @Override
          public void continueChain() {
            fail();
          }

          @Override
          public void continueChain(String authenticationScheme, TokenPrincipal tokenPrincipal) {
            fail();
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors, String message, @Nullable Throwable cause) {
            called.set(true);
            assertThat(errors)
                .containsExactly(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(ALGS));
          }

          @Override
          public void sendError(int statusCode, String message, @Nullable Throwable cause) {
            fail();
          }
        });
    assertThat(called.get()).isTrue();
  }

  @Test
  public void missingDPoPProof() throws Exception {
    var called = new AtomicBoolean();
    var sut = factory.create(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER);

    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of(client.get().toAuthorizationHeader()),
        List.of(),
        null,
        new TokenFilterHelper.FilterChain<Exception>() {
          @Override
          public void continueChain() {
            fail();
          }

          @Override
          public void continueChain(String authenticationScheme, TokenPrincipal tokenPrincipal) {
            fail();
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors, String message, @Nullable Throwable cause) {
            called.set(true);
            assertThat(errors)
                .containsExactly(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(ALGS));
          }

          @Override
          public void sendError(int statusCode, String message, @Nullable Throwable cause) {
            fail();
          }
        });
    assertThat(called.get()).isTrue();
  }

  @Test
  public void tooManyDPoPProofs() throws Exception {
    var called = new AtomicBoolean();
    var sut = factory.create(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER);

    var token = client.get();
    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of(token.toAuthorizationHeader()),
        List.of(
            client.createDPoPJWT(REQUEST_METHOD, REQUEST_URI, token).serialize(),
            client.createDPoPJWT(REQUEST_METHOD, REQUEST_URI, token).serialize()),
        null,
        new TokenFilterHelper.FilterChain<Exception>() {
          @Override
          public void continueChain() {
            fail();
          }

          @Override
          public void continueChain(String authenticationScheme, TokenPrincipal tokenPrincipal) {
            fail();
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors, String message, @Nullable Throwable cause) {
            called.set(true);
            assertThat(errors)
                .containsExactly(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(ALGS));
          }

          @Override
          public void sendError(int statusCode, String message, @Nullable Throwable cause) {
            fail();
          }
        });
    assertThat(called.get()).isTrue();
  }

  @Test
  public void malformedDPoPProof() throws Exception {
    var called = new AtomicBoolean();
    var sut = factory.create(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER);

    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of(client.get().toAuthorizationHeader()),
        List.of("malformed"),
        null,
        new TokenFilterHelper.FilterChain<Exception>() {
          @Override
          public void continueChain() {
            fail();
          }

          @Override
          public void continueChain(String authenticationScheme, TokenPrincipal tokenPrincipal) {
            fail();
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors, String message, @Nullable Throwable cause) {
            called.set(true);
            assertThat(errors)
                .containsExactly(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(ALGS));
          }

          @Override
          public void sendError(int statusCode, String message, @Nullable Throwable cause) {
            fail();
          }
        });
    assertThat(called.get()).isTrue();
  }

  @Test
  public void dpopProofMissingAccessTokenHash() throws Exception {
    var called = new AtomicBoolean();
    var sut = factory.create(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER);

    var token = client.get();
    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of(token.toAuthorizationHeader()),
        List.of(client.createDPoPJWT(REQUEST_METHOD, REQUEST_URI, null).serialize()),
        null,
        new TokenFilterHelper.FilterChain<Exception>() {
          @Override
          public void continueChain() {
            fail();
          }

          @Override
          public void continueChain(String authenticationScheme, TokenPrincipal tokenPrincipal) {
            fail();
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors, String message, @Nullable Throwable cause) {
            called.set(true);
            assertThat(errors)
                .containsExactly(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(ALGS));
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
    var sut = factory.create(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER);
    var chain =
        new TokenFilterHelper.FilterChain<>() {
          @Override
          public void continueChain() {
            fail();
          }

          @Override
          public void continueChain(String authenticationScheme, TokenPrincipal tokenPrincipal) {
            called.set(true);
            assertThat(authenticationScheme).isEqualTo(AccessTokenType.DPOP.getValue());
            assertThat(tokenPrincipal.getTokenInfo().getUsername())
                .isEqualTo("service-account-app");
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors, String message, @Nullable Throwable cause) {
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
        List.of(client.createDPoPJWT(REQUEST_METHOD, REQUEST_URI, token).serialize()),
        null,
        chain);
    assertThat(called.get()).isTrue();

    client.revoke(token);

    called.set(false);
    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of(token.toAuthorizationHeader()),
        List.of(client.createDPoPJWT(REQUEST_METHOD, REQUEST_URI, token).serialize()),
        null,
        chain);

    assertThat(called.get()).isTrue();
  }

  @Test
  public void validTokenNoTokenPrincipal() throws Exception {
    var called = new AtomicBoolean();
    var sut = factory.create(tokenIntrospector, ignored -> null);

    var token = client.get();
    sut.filter(
        REQUEST_METHOD,
        REQUEST_URI,
        List.of(token.toAuthorizationHeader()),
        List.of(client.createDPoPJWT(REQUEST_METHOD, REQUEST_URI, token).serialize()),
        null,
        new TokenFilterHelper.FilterChain<Exception>() {
          @Override
          public void continueChain() {
            called.set(true);
          }

          @Override
          public void continueChain(String authenticationScheme, TokenPrincipal tokenPrincipal) {
            fail();
          }

          @Override
          public void sendError(
              List<TokenSchemeError> errors, String message, @Nullable Throwable cause) {
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
  class BearerInterop {
    @RegisterExtension public BearerTokenExtension bearerClient = new BearerTokenExtension();

    @Test
    public void validBearerTokenUsedAsDPoP() throws Exception {
      var called = new AtomicBoolean();
      var sut = factory.create(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER);

      var token = bearerClient.get();
      sut.filter(
          REQUEST_METHOD,
          REQUEST_URI,
          List.of(new DPoPAccessToken(token.getValue()).toAuthorizationHeader()),
          List.of(client.createDPoPJWT(REQUEST_METHOD, REQUEST_URI, token).serialize()),
          null,
          new TokenFilterHelper.FilterChain<Exception>() {
            @Override
            public void continueChain() {
              fail();
            }

            @Override
            public void continueChain(String authenticationScheme, TokenPrincipal tokenPrincipal) {
              fail();
            }

            @Override
            public void sendError(
                List<TokenSchemeError> errors, String message, @Nullable Throwable cause) {
              called.set(true);
              assertThat(errors)
                  .containsExactly(DPoPTokenError.INVALID_TOKEN.setJWSAlgorithms(ALGS));
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
