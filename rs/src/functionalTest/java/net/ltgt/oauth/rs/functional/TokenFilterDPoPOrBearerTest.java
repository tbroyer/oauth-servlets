package net.ltgt.oauth.rs.functional;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.jupiter.api.Assertions.fail;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.oauth2.sdk.token.DPoPTokenError;
import com.nimbusds.oauth2.sdk.token.TokenSchemeError;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.SecurityContext;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import net.ltgt.oauth.common.CaffeineDPoPSingleUseChecker;
import net.ltgt.oauth.common.DPoPOrBearerTokenFilterHelper;
import net.ltgt.oauth.common.TokenFilterHelper;
import net.ltgt.oauth.common.TokenFilterHelperFactory;
import net.ltgt.oauth.common.TokenPrincipal;
import net.ltgt.oauth.common.fixtures.BearerTokenExtension;
import net.ltgt.oauth.common.fixtures.DPoPTokenExtension;
import org.jboss.resteasy.mock.MockHttpRequest;
import org.jboss.resteasy.mock.MockHttpResponse;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class TokenFilterDPoPOrBearerTest {
  private static final Set<JWSAlgorithm> ALGS = Set.of(JWSAlgorithm.ES256, JWSAlgorithm.PS256);

  @Path("/")
  public static class TestResource {
    @GET
    @Produces(MediaType.TEXT_PLAIN)
    public String get(@Context SecurityContext securityContext) {
      return Optional.ofNullable(securityContext.getUserPrincipal())
          .filter(TokenPrincipal.class::isInstance)
          .map(TokenPrincipal.class::cast)
          .map(tokenPrincipal -> tokenPrincipal.getTokenInfo().getUsername())
          .orElse("null");
    }
  }

  @RegisterExtension
  public WebServerExtension server =
      new WebServerExtension(
          dispatcher -> {
            dispatcher
                .getProviderFactory()
                .property(
                    TokenFilterHelperFactory.CONTEXT_ATTRIBUTE_NAME,
                    new DPoPOrBearerTokenFilterHelper.Factory(
                        ALGS, new CaffeineDPoPSingleUseChecker()));
            dispatcher.getRegistry().addPerRequestResource(TestResource.class);
          });

  private TokenSchemeError parseTokenError(String wwwAuthenticate) {
    try {
      return DPoPTokenError.parse(wwwAuthenticate);
    } catch (ParseException e) {
      try {
        return BearerTokenError.parse(wwwAuthenticate);
      } catch (ParseException ex) {
        throw (RuntimeException)
            fail(
                "WWW-Authenticate header '%s' can't be parsed as either DPoP nor Bearer"
                    .formatted(wwwAuthenticate),
                ex);
      }
    }
  }

  private List<TokenSchemeError> getWwwAuthenticate(MultivaluedMap<String, Object> outputHeaders) {
    return outputHeaders.getOrDefault(HttpHeaders.WWW_AUTHENTICATE, List.of()).stream()
        .map(String.class::cast)
        .map(this::parseTokenError)
        .toList();
  }

  @Test
  public void noAuthentication() throws Exception {
    var request = MockHttpRequest.get("/");
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).isEqualTo("null");
  }

  @Test
  public void badAuthScheme() throws Exception {
    var request =
        MockHttpRequest.get("/")
            .header(
                HttpHeaders.AUTHORIZATION,
                server.getClientAuthentication().toHTTPAuthorizationHeader());
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).isEqualTo("null");
  }

  @Test
  public void badAuthScheme2() throws Exception {
    var request = MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, "dpoptoken");
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).isEqualTo("null");
  }

  @Nested
  class Bearer {
    @RegisterExtension public BearerTokenExtension client = new BearerTokenExtension();

    @Test
    public void missingToken() throws Exception {
      var request = MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, "bearer");
      var response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus())
          .isEqualTo(BearerTokenError.INVALID_REQUEST.getHTTPStatusCode());
      var wwwAuthenticates = getWwwAuthenticate(response.getOutputHeaders());
      assertThat(wwwAuthenticates)
          .containsExactly(
              DPoPTokenError.MISSING_TOKEN.setJWSAlgorithms(ALGS),
              BearerTokenError.INVALID_REQUEST);
    }

    @Test
    public void missingToken2() throws Exception {
      var request = MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, "bearer ");
      var response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus())
          .isEqualTo(BearerTokenError.INVALID_REQUEST.getHTTPStatusCode());
      var wwwAuthenticates = getWwwAuthenticate(response.getOutputHeaders());
      assertThat(wwwAuthenticates)
          .containsExactly(
              DPoPTokenError.MISSING_TOKEN.setJWSAlgorithms(ALGS),
              BearerTokenError.INVALID_REQUEST);
    }

    @Test
    public void invalidToken() throws Exception {
      var request = MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, "bearer invalid");
      var response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus())
          .isEqualTo(BearerTokenError.INVALID_TOKEN.getHTTPStatusCode());
      var wwwAuthenticates = getWwwAuthenticate(response.getOutputHeaders());
      assertThat(wwwAuthenticates)
          .containsExactly(
              DPoPTokenError.MISSING_TOKEN.setJWSAlgorithms(ALGS), BearerTokenError.INVALID_TOKEN);
    }

    @Test
    public void validToken() throws Exception {
      var request =
          MockHttpRequest.get("/")
              .header(HttpHeaders.AUTHORIZATION, client.get().toAuthorizationHeader());
      var response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus()).isEqualTo(200);
      assertThat(response.getContentAsString()).isEqualTo("service-account-app");
    }

    @Test
    public void validTokenInSecondAuthorizationHeader() throws Exception {
      var request =
          MockHttpRequest.get("/")
              .header(
                  HttpHeaders.AUTHORIZATION,
                  server.getClientAuthentication().toHTTPAuthorizationHeader())
              .header(HttpHeaders.AUTHORIZATION, client.get().toAuthorizationHeader());
      var response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus()).isEqualTo(200);
      assertThat(response.getContentAsString()).isEqualTo("service-account-app");
    }

    @Test
    public void revokedButCachedToken() throws Exception {
      var token = client.get();
      var request =
          MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, token.toAuthorizationHeader());
      var response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus()).isEqualTo(200);
      assertThat(response.getContentAsString()).isEqualTo("service-account-app");

      client.revoke(token);

      request =
          MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, token.toAuthorizationHeader());
      response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus()).isEqualTo(200);
      assertThat(response.getContentAsString()).isEqualTo("service-account-app");
    }
  }

  @Nested
  class DPoP {
    @RegisterExtension
    public DPoPTokenExtension client = new DPoPTokenExtension(JWSAlgorithm.ES256);

    @Test
    public void missingToken() throws Exception {
      var request = MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, "dpop");
      var response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus())
          .isEqualTo(DPoPTokenError.INVALID_REQUEST.getHTTPStatusCode());
      var wwwAuthenticates = getWwwAuthenticate(response.getOutputHeaders());
      assertThat(wwwAuthenticates)
          .containsExactly(
              DPoPTokenError.INVALID_REQUEST.setJWSAlgorithms(ALGS),
              BearerTokenError.MISSING_TOKEN);
    }

    @Test
    public void missingToken2() throws Exception {
      var request = MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, "dpop ");
      var response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus())
          .isEqualTo(DPoPTokenError.INVALID_REQUEST.getHTTPStatusCode());
      var wwwAuthenticates = getWwwAuthenticate(response.getOutputHeaders());
      assertThat(wwwAuthenticates)
          .containsExactly(
              DPoPTokenError.INVALID_REQUEST.setJWSAlgorithms(ALGS),
              BearerTokenError.MISSING_TOKEN);
    }

    @Test
    public void invalidToken() throws Exception {
      var request = MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, "dpop invalid");
      request.header(
          TokenFilterHelper.DPOP_HEADER_NAME,
          client
              .createDPoPJWT(
                  request.getHttpMethod(),
                  request.getUri().getAbsolutePath(),
                  new DPoPAccessToken("invalid"))
              .serialize());
      var response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus()).isEqualTo(DPoPTokenError.INVALID_TOKEN.getHTTPStatusCode());
      var wwwAuthenticates = getWwwAuthenticate(response.getOutputHeaders());
      assertThat(wwwAuthenticates)
          .containsExactly(
              DPoPTokenError.INVALID_TOKEN.setJWSAlgorithms(ALGS), BearerTokenError.MISSING_TOKEN);
    }

    @Test
    public void validToken() throws Exception {
      var token = client.get();
      var request =
          MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, token.toAuthorizationHeader());
      request.header(
          TokenFilterHelper.DPOP_HEADER_NAME,
          client
              .createDPoPJWT(request.getHttpMethod(), request.getUri().getAbsolutePath(), token)
              .serialize());
      var response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus()).isEqualTo(200);
      assertThat(response.getContentAsString()).isEqualTo("service-account-app");
    }

    @Test
    public void validTokenInSecondAuthorizationHeader() throws Exception {
      var token = client.get();
      var request =
          MockHttpRequest.get("/")
              .header(
                  HttpHeaders.AUTHORIZATION,
                  server.getClientAuthentication().toHTTPAuthorizationHeader())
              .header(HttpHeaders.AUTHORIZATION, token.toAuthorizationHeader());
      request.header(
          TokenFilterHelper.DPOP_HEADER_NAME,
          client
              .createDPoPJWT(request.getHttpMethod(), request.getUri().getAbsolutePath(), token)
              .serialize());
      var response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus()).isEqualTo(200);
      assertThat(response.getContentAsString()).isEqualTo("service-account-app");
    }

    @Test
    public void invalidDPoPProof() throws Exception {
      var token = client.get();
      var request =
          MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, token.toAuthorizationHeader());
      request.header(
          TokenFilterHelper.DPOP_HEADER_NAME,
          client.createDPoPJWT("POST", request.getUri().getAbsolutePath(), token).serialize());
      var response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus())
          .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.getHTTPStatusCode());
      var wwwAuthenticates = getWwwAuthenticate(response.getOutputHeaders());
      assertThat(wwwAuthenticates)
          .containsExactly(
              DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(ALGS),
              BearerTokenError.MISSING_TOKEN);
    }

    @Test
    public void missingDPoPProof() throws Exception {
      var request =
          MockHttpRequest.get("/")
              .header(HttpHeaders.AUTHORIZATION, client.get().toAuthorizationHeader());
      var response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus())
          .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.getHTTPStatusCode());
      var wwwAuthenticates = getWwwAuthenticate(response.getOutputHeaders());
      assertThat(wwwAuthenticates)
          .containsExactly(
              DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(ALGS),
              BearerTokenError.MISSING_TOKEN);
    }

    @Test
    public void tooManyDPoPProofs() throws Exception {
      var token = client.get();
      var request =
          MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, token.toAuthorizationHeader());
      request.header(
          TokenFilterHelper.DPOP_HEADER_NAME,
          client
              .createDPoPJWT(request.getHttpMethod(), request.getUri().getAbsolutePath(), token)
              .serialize());
      request.header(
          TokenFilterHelper.DPOP_HEADER_NAME,
          client
              .createDPoPJWT(request.getHttpMethod(), request.getUri().getAbsolutePath(), token)
              .serialize());
      var response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus())
          .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.getHTTPStatusCode());
      var wwwAuthenticates = getWwwAuthenticate(response.getOutputHeaders());
      assertThat(wwwAuthenticates)
          .containsExactly(
              DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(ALGS),
              BearerTokenError.MISSING_TOKEN);
    }

    @Test
    public void malformedDPoPProof() throws Exception {
      var request =
          MockHttpRequest.get("/")
              .header(HttpHeaders.AUTHORIZATION, client.get().toAuthorizationHeader());
      request.header(TokenFilterHelper.DPOP_HEADER_NAME, "malformed");
      var response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus())
          .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.getHTTPStatusCode());
      var wwwAuthenticates = getWwwAuthenticate(response.getOutputHeaders());
      assertThat(wwwAuthenticates)
          .containsExactly(
              DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(ALGS),
              BearerTokenError.MISSING_TOKEN);
    }

    @Test
    public void dpopProofMissingAccessTokenHash() throws Exception {
      var request =
          MockHttpRequest.get("/")
              .header(HttpHeaders.AUTHORIZATION, client.get().toAuthorizationHeader());
      request.header(
          TokenFilterHelper.DPOP_HEADER_NAME,
          client
              .createDPoPJWT(request.getHttpMethod(), request.getUri().getAbsolutePath(), null)
              .serialize());
      var response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus())
          .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.getHTTPStatusCode());
      var wwwAuthenticates = getWwwAuthenticate(response.getOutputHeaders());
      assertThat(wwwAuthenticates)
          .containsExactly(
              DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(ALGS),
              BearerTokenError.MISSING_TOKEN);
    }

    @Test
    public void replayedDPoPProof() throws Exception {
      var token = client.get();
      var request =
          MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, token.toAuthorizationHeader());
      request.header(
          TokenFilterHelper.DPOP_HEADER_NAME,
          client
              .createDPoPJWT(request.getHttpMethod(), request.getUri().getAbsolutePath(), token)
              .serialize());

      var response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus()).isEqualTo(200);
      assertThat(response.getContentAsString()).isEqualTo("service-account-app");

      response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus())
          .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.getHTTPStatusCode());
      var wwwAuthenticates = getWwwAuthenticate(response.getOutputHeaders());
      assertThat(wwwAuthenticates)
          .containsExactly(
              DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(ALGS),
              BearerTokenError.MISSING_TOKEN);
    }

    @Test
    public void revokedButCachedToken() throws Exception {
      var token = client.get();
      var request =
          MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, token.toAuthorizationHeader());
      request.header(
          TokenFilterHelper.DPOP_HEADER_NAME,
          client
              .createDPoPJWT(request.getHttpMethod(), request.getUri().getAbsolutePath(), token)
              .serialize());
      var response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus()).isEqualTo(200);
      assertThat(response.getContentAsString()).isEqualTo("service-account-app");

      client.revoke(token);

      request =
          MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, token.toAuthorizationHeader());
      request.header(
          TokenFilterHelper.DPOP_HEADER_NAME,
          client
              .createDPoPJWT(request.getHttpMethod(), request.getUri().getAbsolutePath(), token)
              .serialize());
      response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus()).isEqualTo(200);
      assertThat(response.getContentAsString()).isEqualTo("service-account-app");
    }
  }

  @Nested
  class BearerInterop {
    @RegisterExtension
    public DPoPTokenExtension dpopClient = new DPoPTokenExtension(JWSAlgorithm.ES256);

    @RegisterExtension public BearerTokenExtension bearerClient = new BearerTokenExtension();

    @Test
    public void validDPoPTokenUsedAsBearer() throws Exception {
      var request =
          MockHttpRequest.get("/")
              .header(
                  HttpHeaders.AUTHORIZATION,
                  new BearerAccessToken(dpopClient.get().getValue()).toAuthorizationHeader());
      var response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus())
          .isEqualTo(BearerTokenError.INVALID_TOKEN.getHTTPStatusCode());
      var wwwAuthenticates = getWwwAuthenticate(response.getOutputHeaders());
      assertThat(wwwAuthenticates)
          .containsExactly(
              DPoPTokenError.MISSING_TOKEN.setJWSAlgorithms(ALGS), BearerTokenError.INVALID_TOKEN);
    }

    @Test
    public void validBearerTokenUsedAsDPoP() throws Exception {
      var token = bearerClient.get();
      var request =
          MockHttpRequest.get("/")
              .header(
                  HttpHeaders.AUTHORIZATION,
                  new DPoPAccessToken(token.getValue()).toAuthorizationHeader());
      request.header(
          TokenFilterHelper.DPOP_HEADER_NAME,
          dpopClient
              .createDPoPJWT(request.getHttpMethod(), request.getUri().getAbsolutePath(), token)
              .serialize());
      var response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus()).isEqualTo(DPoPTokenError.INVALID_TOKEN.getHTTPStatusCode());
      var wwwAuthenticates = getWwwAuthenticate(response.getOutputHeaders());
      assertThat(wwwAuthenticates)
          .containsExactly(
              DPoPTokenError.INVALID_TOKEN.setJWSAlgorithms(ALGS), BearerTokenError.MISSING_TOKEN);
    }

    @Test
    public void validDPoPTokenUsedAsBothBearerAndDPoP() throws Exception {
      var token = dpopClient.get();
      var request =
          MockHttpRequest.get("/")
              .header(HttpHeaders.AUTHORIZATION, token.toAuthorizationHeader())
              .header(
                  HttpHeaders.AUTHORIZATION,
                  new BearerAccessToken(token.getValue()).toAuthorizationHeader());
      request.header(
          TokenFilterHelper.DPOP_HEADER_NAME,
          dpopClient
              .createDPoPJWT(request.getHttpMethod(), request.getUri().getAbsolutePath(), token)
              .serialize());
      var response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus())
          .isEqualTo(BearerTokenError.INVALID_REQUEST.getHTTPStatusCode());
      var wwwAuthenticates = getWwwAuthenticate(response.getOutputHeaders());
      assertThat(wwwAuthenticates)
          .containsExactly(
              DPoPTokenError.INVALID_REQUEST
                  .setJWSAlgorithms(ALGS)
                  .setDescription("Multiple methods used to include access token"),
              BearerTokenError.INVALID_REQUEST.setDescription(
                  "Multiple methods used to include access token"));
    }

    @Test
    public void validBearerTokenUsedAsBothBearerAndDPoP() throws Exception {
      var token = bearerClient.get();
      var request =
          MockHttpRequest.get("/")
              .header(HttpHeaders.AUTHORIZATION, token.toAuthorizationHeader())
              .header(
                  HttpHeaders.AUTHORIZATION,
                  new DPoPAccessToken(token.getValue()).toAuthorizationHeader());
      request.header(
          TokenFilterHelper.DPOP_HEADER_NAME,
          dpopClient
              .createDPoPJWT(request.getHttpMethod(), request.getUri().getAbsolutePath(), token)
              .serialize());
      var response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus())
          .isEqualTo(DPoPTokenError.INVALID_REQUEST.getHTTPStatusCode());
      var wwwAuthenticates = getWwwAuthenticate(response.getOutputHeaders());
      assertThat(wwwAuthenticates)
          .containsExactly(
              DPoPTokenError.INVALID_REQUEST
                  .setJWSAlgorithms(ALGS)
                  .setDescription("Multiple methods used to include access token"),
              BearerTokenError.INVALID_REQUEST.setDescription(
                  "Multiple methods used to include access token"));
    }

    @Test
    public void includingBothValidBearerAndValidDPoPTokens() throws Exception {
      var dpopToken = dpopClient.get();
      var request =
          MockHttpRequest.get("/")
              .header(HttpHeaders.AUTHORIZATION, bearerClient.get().toAuthorizationHeader())
              .header(HttpHeaders.AUTHORIZATION, dpopToken.toAuthorizationHeader());
      request.header(
          TokenFilterHelper.DPOP_HEADER_NAME,
          dpopClient
              .createDPoPJWT(request.getHttpMethod(), request.getUri().getAbsolutePath(), dpopToken)
              .serialize());
      var response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus())
          .isEqualTo(DPoPTokenError.INVALID_REQUEST.getHTTPStatusCode());
      var wwwAuthenticates = getWwwAuthenticate(response.getOutputHeaders());
      assertThat(wwwAuthenticates)
          .containsExactly(
              DPoPTokenError.INVALID_REQUEST
                  .setJWSAlgorithms(ALGS)
                  .setDescription("Multiple methods used to include access token"),
              BearerTokenError.INVALID_REQUEST.setDescription(
                  "Multiple methods used to include access token"));
    }
  }
}
