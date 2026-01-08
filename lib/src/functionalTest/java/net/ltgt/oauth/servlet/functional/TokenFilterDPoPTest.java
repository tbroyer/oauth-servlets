package net.ltgt.oauth.servlet.functional;

import static com.google.common.truth.Truth.assertThat;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.oauth2.sdk.token.DPoPTokenError;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.Set;
import net.ltgt.oauth.common.CaffeineDPoPSingleUseChecker;
import net.ltgt.oauth.common.DPoPTokenFilterHelper;
import net.ltgt.oauth.common.TokenFilterHelper;
import net.ltgt.oauth.common.TokenFilterHelperFactory;
import net.ltgt.oauth.common.TokenPrincipal;
import net.ltgt.oauth.common.fixtures.BearerTokenExtension;
import net.ltgt.oauth.common.fixtures.DPoPTokenExtension;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpTester;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class TokenFilterDPoPTest {
  private static final Set<JWSAlgorithm> ALGS = Set.of(JWSAlgorithm.ES256, JWSAlgorithm.PS256);

  @RegisterExtension
  public WebServerExtension server =
      new WebServerExtension(
          contextHandler -> {
            contextHandler.setAttribute(
                TokenFilterHelperFactory.CONTEXT_ATTRIBUTE_NAME,
                new DPoPTokenFilterHelper.Factory(ALGS, new CaffeineDPoPSingleUseChecker()));
            contextHandler.addServlet(
                new HttpServlet() {
                  @Override
                  protected void doGet(HttpServletRequest req, HttpServletResponse resp)
                      throws ServletException, IOException {
                    resp.getWriter()
                        .print(
                            Optional.ofNullable(req.getUserPrincipal())
                                .filter(TokenPrincipal.class::isInstance)
                                .map(TokenPrincipal.class::cast)
                                .map(tokenPrincipal -> tokenPrincipal.getTokenInfo().getUsername())
                                .orElse(null));
                  }
                },
                "/");
          });

  @RegisterExtension public DPoPTokenExtension client = new DPoPTokenExtension(JWSAlgorithm.ES256);

  @Test
  public void noAuthentication() throws Exception {
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    var response = server.getResponse(request);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContent()).isEqualTo("null");
  }

  @Test
  public void badAuthScheme() throws Exception {
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(
        HttpHeader.AUTHORIZATION, server.getClientAuthentication().toHTTPAuthorizationHeader());
    var response = server.getResponse(request);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContent()).isEqualTo("null");
  }

  @Test
  public void badAuthScheme2() throws Exception {
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(HttpHeader.AUTHORIZATION, "dpoptoken");
    var response = server.getResponse(request);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContent()).isEqualTo("null");
  }

  @Test
  public void missingToken() throws Exception {
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(HttpHeader.AUTHORIZATION, "dpop");
    var response = server.getResponse(request);
    assertThat(response.getStatus()).isEqualTo(DPoPTokenError.INVALID_REQUEST.getHTTPStatusCode());
    var wwwAuthenticate = response.get(HttpHeader.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isNotNull();
    assertThat(DPoPTokenError.parse(wwwAuthenticate))
        .isEqualTo(DPoPTokenError.INVALID_REQUEST.setJWSAlgorithms(ALGS));
  }

  @Test
  public void missingToken2() throws Exception {
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(HttpHeader.AUTHORIZATION, "dpop ");
    var response = server.getResponse(request);
    assertThat(response.getStatus()).isEqualTo(DPoPTokenError.INVALID_REQUEST.getHTTPStatusCode());
    var wwwAuthenticate = response.get(HttpHeader.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isNotNull();
    assertThat(DPoPTokenError.parse(wwwAuthenticate))
        .isEqualTo(DPoPTokenError.INVALID_REQUEST.setJWSAlgorithms(ALGS));
  }

  @Test
  public void invalidToken() throws Exception {
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(HttpHeader.AUTHORIZATION, "dpop invalid");
    request.put(
        TokenFilterHelper.DPOP_HEADER_NAME,
        client
            .createDPoPJWT(
                request.getMethod(),
                server.getURI(request.getURI()),
                new DPoPAccessToken("invalid"))
            .serialize());
    var response = server.getResponse(request);
    assertThat(response.getStatus()).isEqualTo(DPoPTokenError.INVALID_TOKEN.getHTTPStatusCode());
    var wwwAuthenticate = response.get(HttpHeader.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isNotNull();
    assertThat(DPoPTokenError.parse(wwwAuthenticate))
        .isEqualTo(DPoPTokenError.INVALID_TOKEN.setJWSAlgorithms(ALGS));
  }

  @Test
  public void validToken() throws Exception {
    var token = client.get();
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(HttpHeader.AUTHORIZATION, token.toAuthorizationHeader());
    request.put(
        TokenFilterHelper.DPOP_HEADER_NAME,
        client
            .createDPoPJWT(request.getMethod(), server.getURI(request.getURI()), token)
            .serialize());
    var response = server.getResponse(request);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContent()).isEqualTo("service-account-app");
  }

  @Test
  public void validTokenInSecondAuthorizationHeader() throws Exception {
    var token = client.get();
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.add(
        HttpHeader.AUTHORIZATION, server.getClientAuthentication().toHTTPAuthorizationHeader());
    request.add(HttpHeader.AUTHORIZATION, token.toAuthorizationHeader());
    request.put(
        TokenFilterHelper.DPOP_HEADER_NAME,
        client
            .createDPoPJWT(request.getMethod(), server.getURI(request.getURI()), token)
            .serialize());
    var response = server.getResponse(request);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContent()).isEqualTo("service-account-app");
  }

  @Test
  public void invalidDPoPProof() throws Exception {
    var token = client.get();
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(HttpHeader.AUTHORIZATION, token.toAuthorizationHeader());
    request.put(
        TokenFilterHelper.DPOP_HEADER_NAME,
        client.createDPoPJWT("POST", server.getURI(request.getURI()), token).serialize());
    var response = server.getResponse(request);
    assertThat(response.getStatus())
        .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.getHTTPStatusCode());
    var wwwAuthenticate = response.get(HttpHeader.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isNotNull();
    assertThat(DPoPTokenError.parse(wwwAuthenticate))
        .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(ALGS));
  }

  @Test
  public void missingDPoPProof() throws Exception {
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(HttpHeader.AUTHORIZATION, client.get().toAuthorizationHeader());
    var response = server.getResponse(request);
    assertThat(response.getStatus())
        .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.getHTTPStatusCode());
    var wwwAuthenticate = response.get(HttpHeader.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isNotNull();
    assertThat(DPoPTokenError.parse(wwwAuthenticate))
        .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(ALGS));
  }

  @Test
  public void tooManyDPoPProofs() throws Exception {
    var token = client.get();
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(HttpHeader.AUTHORIZATION, token.toAuthorizationHeader());
    request.add(
        TokenFilterHelper.DPOP_HEADER_NAME,
        client
            .createDPoPJWT(request.getMethod(), server.getURI(request.getURI()), token)
            .serialize());
    request.add(
        TokenFilterHelper.DPOP_HEADER_NAME,
        client
            .createDPoPJWT(request.getMethod(), server.getURI(request.getURI()), token)
            .serialize());
    var response = server.getResponse(request);
    assertThat(response.getStatus())
        .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.getHTTPStatusCode());
    var wwwAuthenticate = response.get(HttpHeader.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isNotNull();
    assertThat(DPoPTokenError.parse(wwwAuthenticate))
        .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(ALGS));
  }

  @Test
  public void malformedDPoPProof() throws Exception {
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(HttpHeader.AUTHORIZATION, client.get().toAuthorizationHeader());
    request.put(TokenFilterHelper.DPOP_HEADER_NAME, "malformed");
    var response = server.getResponse(request);
    assertThat(response.getStatus())
        .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.getHTTPStatusCode());
    var wwwAuthenticate = response.get(HttpHeader.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isNotNull();
    assertThat(DPoPTokenError.parse(wwwAuthenticate))
        .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(ALGS));
  }

  @Test
  public void dpopProofMissingAccessTokenHash() throws Exception {
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(HttpHeader.AUTHORIZATION, client.get().toAuthorizationHeader());
    request.put(
        TokenFilterHelper.DPOP_HEADER_NAME,
        client
            .createDPoPJWT(request.getMethod(), server.getURI(request.getURI()), null)
            .serialize());
    var response = server.getResponse(request);
    assertThat(response.getStatus())
        .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.getHTTPStatusCode());
    var wwwAuthenticate = response.get(HttpHeader.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isNotNull();
    assertThat(DPoPTokenError.parse(wwwAuthenticate))
        .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(ALGS));
  }

  @Test
  public void replayedDPoPProof() throws Exception {
    var token = client.get();
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(HttpHeader.AUTHORIZATION, token.toAuthorizationHeader());
    request.put(
        TokenFilterHelper.DPOP_HEADER_NAME,
        client
            .createDPoPJWT(request.getMethod(), server.getURI(request.getURI()), token)
            .serialize());

    var response = server.getResponse(request);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContent()).isEqualTo("service-account-app");

    response = server.getResponse(request);
    assertThat(response.getStatus())
        .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.getHTTPStatusCode());
    var wwwAuthenticate = response.get(HttpHeader.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isNotNull();
    assertThat(DPoPTokenError.parse(wwwAuthenticate))
        .isEqualTo(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(ALGS));
  }

  @Test
  public void revokedButCachedToken() throws Exception {
    var token = client.get();
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(HttpHeader.AUTHORIZATION, token.toAuthorizationHeader());
    request.put(
        TokenFilterHelper.DPOP_HEADER_NAME,
        client
            .createDPoPJWT(request.getMethod(), server.getURI(request.getURI()), token)
            .serialize());
    var response = server.getResponse(request);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContent()).isEqualTo("service-account-app");

    client.revoke(token);

    request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(HttpHeader.AUTHORIZATION, token.toAuthorizationHeader());
    request.put(
        TokenFilterHelper.DPOP_HEADER_NAME,
        client
            .createDPoPJWT(request.getMethod(), server.getURI(request.getURI()), token)
            .serialize());
    response = server.getResponse(request);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContent()).isEqualTo("service-account-app");
  }

  @Nested
  class BearerInterop {
    @RegisterExtension public BearerTokenExtension bearerClient = new BearerTokenExtension();

    @Test
    public void validBearerTokenUsedAsDPoP() throws Exception {
      var token = bearerClient.get();
      var request = HttpTester.newRequest();
      request.setMethod("GET");
      request.setURI("/");
      request.put(
          HttpHeader.AUTHORIZATION, new DPoPAccessToken(token.getValue()).toAuthorizationHeader());
      request.put(
          TokenFilterHelper.DPOP_HEADER_NAME,
          client
              .createDPoPJWT(request.getMethod(), server.getURI(request.getURI()), token)
              .serialize());
      var response = server.getResponse(request);
      assertThat(response.getStatus()).isEqualTo(DPoPTokenError.INVALID_TOKEN.getHTTPStatusCode());
      var wwwAuthenticate = response.get(HttpHeader.WWW_AUTHENTICATE);
      assertThat(wwwAuthenticate).isNotNull();
      assertThat(DPoPTokenError.parse(wwwAuthenticate))
          .isEqualTo(DPoPTokenError.INVALID_TOKEN.setJWSAlgorithms(ALGS));
    }
  }
}
