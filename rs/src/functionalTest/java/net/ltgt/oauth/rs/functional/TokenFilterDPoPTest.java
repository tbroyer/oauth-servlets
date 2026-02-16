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
package net.ltgt.oauth.rs.functional;

import static com.google.common.truth.Truth.assertThat;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.oauth2.sdk.token.DPoPTokenError;
import com.nimbusds.openid.connect.sdk.Nonce;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.SecurityContext;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import net.ltgt.oauth.common.CaffeineDPoPSingleUseChecker;
import net.ltgt.oauth.common.TokenFilterHelper;
import net.ltgt.oauth.common.TokenPrincipal;
import net.ltgt.oauth.common.TokenTypeSupport;
import net.ltgt.oauth.common.fixtures.BearerTokenExtension;
import net.ltgt.oauth.common.fixtures.DPoPTokenExtension;
import org.jboss.resteasy.mock.MockHttpRequest;
import org.jboss.resteasy.mock.MockHttpResponse;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class TokenFilterDPoPTest {
  private static final Set<JWSAlgorithm> ALGS = Set.of(JWSAlgorithm.ES256, JWSAlgorithm.PS256);
  private static final Nonce OLD_NONCE = new Nonce();
  private static final Nonce CURRENT_NONCE = new Nonce();

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
                    TokenTypeSupport.CONTEXT_ATTRIBUTE_NAME,
                    TokenTypeSupport.dpop(
                        ALGS,
                        new CaffeineDPoPSingleUseChecker(),
                        () -> List.of(CURRENT_NONCE, OLD_NONCE)));
            dispatcher.getRegistry().addPerRequestResource(TestResource.class);
          });

  @RegisterExtension public DPoPTokenExtension client = new DPoPTokenExtension(JWSAlgorithm.ES256);

  @Test
  public void noAuthentication() throws Exception {
    var request = MockHttpRequest.get("/");
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).isEqualTo("null");
    assertThat(response.getOutputHeaders())
        .doesNotContainKey(TokenFilterHelper.DPOP_NONCE_HEADER_NAME);
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
    assertThat(response.getOutputHeaders())
        .doesNotContainKey(TokenFilterHelper.DPOP_NONCE_HEADER_NAME);
  }

  @Test
  public void badAuthScheme2() throws Exception {
    var request = MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, "dpoptoken");
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).isEqualTo("null");
    assertThat(response.getOutputHeaders())
        .doesNotContainKey(TokenFilterHelper.DPOP_NONCE_HEADER_NAME);
  }

  @Test
  public void missingToken() throws Exception {
    var request = MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, "dpop");
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(DPoPTokenError.INVALID_REQUEST.getHTTPStatusCode());
    var wwwAuthenticate = response.getOutputHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isInstanceOf(String.class);
    assertThat(DPoPTokenError.parse((String) wwwAuthenticate))
        .isEqualTo(DPoPTokenError.INVALID_REQUEST.setJWSAlgorithms(ALGS));
    assertThat(response.getOutputHeaders())
        .doesNotContainKey(TokenFilterHelper.DPOP_NONCE_HEADER_NAME);
  }

  @Test
  public void missingToken2() throws Exception {
    var request = MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, "dpop ");
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(DPoPTokenError.INVALID_REQUEST.getHTTPStatusCode());
    var wwwAuthenticate = response.getOutputHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isInstanceOf(String.class);
    assertThat(DPoPTokenError.parse((String) wwwAuthenticate))
        .isEqualTo(DPoPTokenError.INVALID_REQUEST.setJWSAlgorithms(ALGS));
    assertThat(response.getOutputHeaders())
        .doesNotContainKey(TokenFilterHelper.DPOP_NONCE_HEADER_NAME);
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
                new DPoPAccessToken("invalid"),
                CURRENT_NONCE)
            .serialize());
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(DPoPTokenError.INVALID_TOKEN.getHTTPStatusCode());
    var wwwAuthenticate = response.getOutputHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isInstanceOf(String.class);
    assertThat(DPoPTokenError.parse((String) wwwAuthenticate))
        .isEqualTo(DPoPTokenError.INVALID_TOKEN.setJWSAlgorithms(ALGS));
    assertThat(response.getOutputHeaders())
        .doesNotContainKey(TokenFilterHelper.DPOP_NONCE_HEADER_NAME);
  }

  @Test
  public void validToken() throws Exception {
    var token = client.get();
    var request =
        MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, token.toAuthorizationHeader());
    request.header(
        TokenFilterHelper.DPOP_HEADER_NAME,
        client
            .createDPoPJWT(
                request.getHttpMethod(), request.getUri().getAbsolutePath(), token, CURRENT_NONCE)
            .serialize());
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).isEqualTo("service-account-app");
    assertThat(response.getOutputHeaders())
        .doesNotContainKey(TokenFilterHelper.DPOP_NONCE_HEADER_NAME);
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
            .createDPoPJWT(
                request.getHttpMethod(), request.getUri().getAbsolutePath(), token, CURRENT_NONCE)
            .serialize());
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).isEqualTo("service-account-app");
    assertThat(response.getOutputHeaders())
        .doesNotContainKey(TokenFilterHelper.DPOP_NONCE_HEADER_NAME);
  }

  @Test
  public void oldNonce() throws Exception {
    var token = client.get();
    var request =
        MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, token.toAuthorizationHeader());
    request.header(
        TokenFilterHelper.DPOP_HEADER_NAME,
        client
            .createDPoPJWT(
                request.getHttpMethod(), request.getUri().getAbsolutePath(), token, OLD_NONCE)
            .serialize());
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).isEqualTo("service-account-app");
    assertThat(
            response
                .getOutputHeaders()
                .getOrDefault(TokenFilterHelper.DPOP_NONCE_HEADER_NAME, List.of())
                .stream()
                .map(String.class::cast)
                .toList())
        .containsExactly(CURRENT_NONCE.getValue());
  }

  @Test
  public void invalidDPoPProof() throws Exception {
    var token = client.get();
    var request =
        MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, token.toAuthorizationHeader());
    request.header(
        TokenFilterHelper.DPOP_HEADER_NAME,
        client
            .createDPoPJWT("POST", request.getUri().getAbsolutePath(), token, CURRENT_NONCE)
            .serialize());
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus())
        .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.getHTTPStatusCode());
    var wwwAuthenticate = response.getOutputHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isInstanceOf(String.class);
    assertThat(DPoPTokenError.parse((String) wwwAuthenticate))
        .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(ALGS));
    assertThat(response.getOutputHeaders())
        .doesNotContainKey(TokenFilterHelper.DPOP_NONCE_HEADER_NAME);
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
    var wwwAuthenticate = response.getOutputHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isInstanceOf(String.class);
    assertThat(DPoPTokenError.parse((String) wwwAuthenticate))
        .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(ALGS));
    assertThat(response.getOutputHeaders())
        .doesNotContainKey(TokenFilterHelper.DPOP_NONCE_HEADER_NAME);
  }

  @Test
  public void tooManyDPoPProofs() throws Exception {
    var token = client.get();
    var request =
        MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, token.toAuthorizationHeader());
    request.header(
        TokenFilterHelper.DPOP_HEADER_NAME,
        client
            .createDPoPJWT(
                request.getHttpMethod(), request.getUri().getAbsolutePath(), token, CURRENT_NONCE)
            .serialize());
    request.header(
        TokenFilterHelper.DPOP_HEADER_NAME,
        client
            .createDPoPJWT(
                request.getHttpMethod(), request.getUri().getAbsolutePath(), token, CURRENT_NONCE)
            .serialize());
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus())
        .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.getHTTPStatusCode());
    var wwwAuthenticate = response.getOutputHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isInstanceOf(String.class);
    assertThat(DPoPTokenError.parse((String) wwwAuthenticate))
        .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(ALGS));
    assertThat(response.getOutputHeaders())
        .doesNotContainKey(TokenFilterHelper.DPOP_NONCE_HEADER_NAME);
  }

  @Test
  public void malformedDPoPProof() throws Exception {
    var token = client.get();
    var request =
        MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, token.toAuthorizationHeader());
    request.header(TokenFilterHelper.DPOP_HEADER_NAME, "malformed");
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus())
        .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.getHTTPStatusCode());
    var wwwAuthenticate = response.getOutputHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isInstanceOf(String.class);
    assertThat(DPoPTokenError.parse((String) wwwAuthenticate))
        .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(ALGS));
    assertThat(response.getOutputHeaders())
        .doesNotContainKey(TokenFilterHelper.DPOP_NONCE_HEADER_NAME);
  }

  @Test
  public void dpopProofMissingAccessTokenHash() throws Exception {
    var request =
        MockHttpRequest.get("/")
            .header(HttpHeaders.AUTHORIZATION, client.get().toAuthorizationHeader());
    request.header(
        TokenFilterHelper.DPOP_HEADER_NAME,
        client
            .createDPoPJWT(
                request.getHttpMethod(), request.getUri().getAbsolutePath(), null, CURRENT_NONCE)
            .serialize());
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus())
        .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.getHTTPStatusCode());
    var wwwAuthenticate = response.getOutputHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isInstanceOf(String.class);
    assertThat(DPoPTokenError.parse((String) wwwAuthenticate))
        .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(ALGS));
    assertThat(response.getOutputHeaders())
        .doesNotContainKey(TokenFilterHelper.DPOP_NONCE_HEADER_NAME);
  }

  @Test
  public void missingNonce() throws Exception {
    var token = client.get();
    var request =
        MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, token.toAuthorizationHeader());
    request.header(
        TokenFilterHelper.DPOP_HEADER_NAME,
        client
            .createDPoPJWT(request.getHttpMethod(), request.getUri().getAbsolutePath(), token, null)
            .serialize());
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(DPoPTokenError.USE_DPOP_NONCE.getHTTPStatusCode());
    var wwwAuthenticate = response.getOutputHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isInstanceOf(String.class);
    assertThat(DPoPTokenError.parse((String) wwwAuthenticate))
        .isEqualTo(DPoPTokenError.USE_DPOP_NONCE.setJWSAlgorithms(ALGS));
    assertThat(
            response
                .getOutputHeaders()
                .getOrDefault(TokenFilterHelper.DPOP_NONCE_HEADER_NAME, List.of())
                .stream()
                .map(String.class::cast)
                .toList())
        .containsExactly(CURRENT_NONCE.getValue());
  }

  @Test
  public void badNonce() throws Exception {
    var token = client.get();
    var request =
        MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, token.toAuthorizationHeader());
    request.header(
        TokenFilterHelper.DPOP_HEADER_NAME,
        client
            .createDPoPJWT(
                request.getHttpMethod(), request.getUri().getAbsolutePath(), token, new Nonce())
            .serialize());
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(DPoPTokenError.USE_DPOP_NONCE.getHTTPStatusCode());
    var wwwAuthenticate = response.getOutputHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isInstanceOf(String.class);
    assertThat(DPoPTokenError.parse((String) wwwAuthenticate))
        .isEqualTo(DPoPTokenError.USE_DPOP_NONCE.setJWSAlgorithms(ALGS));
    assertThat(
            response
                .getOutputHeaders()
                .getOrDefault(TokenFilterHelper.DPOP_NONCE_HEADER_NAME, List.of())
                .stream()
                .map(String.class::cast)
                .toList())
        .containsExactly(CURRENT_NONCE.getValue());
  }

  @Test
  public void invalidDPoPProofWithBadNonce() throws Exception {
    var token = client.get();
    var request =
        MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, token.toAuthorizationHeader());
    request.header(
        TokenFilterHelper.DPOP_HEADER_NAME,
        client
            .createDPoPJWT("POST", request.getUri().getAbsolutePath(), token, new Nonce())
            .serialize());
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus())
        .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.getHTTPStatusCode());
    var wwwAuthenticate = response.getOutputHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isInstanceOf(String.class);
    assertThat(DPoPTokenError.parse((String) wwwAuthenticate))
        .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(ALGS));
    assertThat(response.getOutputHeaders())
        .doesNotContainKey(TokenFilterHelper.DPOP_NONCE_HEADER_NAME);
  }

  @Test
  public void replayedDPoPProof() throws Exception {
    var token = client.get();
    var request =
        MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, token.toAuthorizationHeader());
    request.header(
        TokenFilterHelper.DPOP_HEADER_NAME,
        client
            .createDPoPJWT(
                request.getHttpMethod(), request.getUri().getAbsolutePath(), token, CURRENT_NONCE)
            .serialize());

    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).isEqualTo("service-account-app");
    assertThat(response.getOutputHeaders())
        .doesNotContainKey(TokenFilterHelper.DPOP_NONCE_HEADER_NAME);

    response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus())
        .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.getHTTPStatusCode());
    var wwwAuthenticate = response.getOutputHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isInstanceOf(String.class);
    assertThat(DPoPTokenError.parse((String) wwwAuthenticate))
        .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(ALGS));
    assertThat(response.getOutputHeaders())
        .doesNotContainKey(TokenFilterHelper.DPOP_NONCE_HEADER_NAME);
  }

  @Test
  public void revokedButCachedToken() throws Exception {
    var token = client.get();
    var request =
        MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, token.toAuthorizationHeader());
    request.header(
        TokenFilterHelper.DPOP_HEADER_NAME,
        client
            .createDPoPJWT(
                request.getHttpMethod(), request.getUri().getAbsolutePath(), token, CURRENT_NONCE)
            .serialize());
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).isEqualTo("service-account-app");
    assertThat(response.getOutputHeaders())
        .doesNotContainKey(TokenFilterHelper.DPOP_NONCE_HEADER_NAME);

    client.revoke(token);

    request =
        MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, token.toAuthorizationHeader());
    request.header(
        TokenFilterHelper.DPOP_HEADER_NAME,
        client
            .createDPoPJWT(
                request.getHttpMethod(), request.getUri().getAbsolutePath(), token, CURRENT_NONCE)
            .serialize());
    response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).isEqualTo("service-account-app");
    assertThat(response.getOutputHeaders())
        .doesNotContainKey(TokenFilterHelper.DPOP_NONCE_HEADER_NAME);
  }

  @Nested
  class BearerInterop {
    @RegisterExtension public BearerTokenExtension bearerClient = new BearerTokenExtension();

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
          client
              .createDPoPJWT(
                  request.getHttpMethod(), request.getUri().getAbsolutePath(), token, CURRENT_NONCE)
              .serialize());
      var response = new MockHttpResponse();
      server.invoke(request, response);
      assertThat(response.getStatus()).isEqualTo(DPoPTokenError.INVALID_TOKEN.getHTTPStatusCode());
      var wwwAuthenticate = response.getOutputHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
      assertThat(wwwAuthenticate).isInstanceOf(String.class);
      assertThat(DPoPTokenError.parse((String) wwwAuthenticate))
          .isEqualTo(DPoPTokenError.INVALID_TOKEN.setJWSAlgorithms(ALGS));
      assertThat(response.getOutputHeaders())
          .doesNotContainKey(TokenFilterHelper.DPOP_NONCE_HEADER_NAME);
    }
  }
}
