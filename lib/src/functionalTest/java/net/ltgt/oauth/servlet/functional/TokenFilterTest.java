package net.ltgt.oauth.servlet.functional;

import static com.google.common.truth.Truth.assertThat;

import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import net.ltgt.oauth.common.TokenFilterHelper;
import net.ltgt.oauth.common.TokenPrincipal;
import net.ltgt.oauth.common.fixtures.BearerTokenExtension;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpTester;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class TokenFilterTest {
  @RegisterExtension
  public WebServerExtension server =
      new WebServerExtension(
          contextHandler -> {
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

  @RegisterExtension public BearerTokenExtension client = new BearerTokenExtension();

  @Test
  public void noAuthentication() throws Exception {
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    var response = server.getResponse(request);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContent()).isEqualTo("null");
    assertThat(response.contains(TokenFilterHelper.DPOP_NONCE_HEADER_NAME)).isFalse();
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
    assertThat(response.contains(TokenFilterHelper.DPOP_NONCE_HEADER_NAME)).isFalse();
  }

  @Test
  public void badAuthScheme2() throws Exception {
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(HttpHeader.AUTHORIZATION, "bearertoken");
    var response = server.getResponse(request);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContent()).isEqualTo("null");
    assertThat(response.contains(TokenFilterHelper.DPOP_NONCE_HEADER_NAME)).isFalse();
  }

  @Test
  public void missingToken() throws Exception {
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(HttpHeader.AUTHORIZATION, "bearer");
    var response = server.getResponse(request);
    assertThat(response.getStatus())
        .isEqualTo(BearerTokenError.INVALID_REQUEST.getHTTPStatusCode());
    var wwwAuthenticate = response.get(HttpHeader.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isNotNull();
    assertThat(BearerTokenError.parse(wwwAuthenticate)).isEqualTo(BearerTokenError.INVALID_REQUEST);
    assertThat(response.contains(TokenFilterHelper.DPOP_NONCE_HEADER_NAME)).isFalse();
  }

  @Test
  public void missingToken2() throws Exception {
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(HttpHeader.AUTHORIZATION, "bearer ");
    var response = server.getResponse(request);
    assertThat(response.getStatus())
        .isEqualTo(BearerTokenError.INVALID_REQUEST.getHTTPStatusCode());
    var wwwAuthenticate = response.get(HttpHeader.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isNotNull();
    assertThat(BearerTokenError.parse(wwwAuthenticate)).isEqualTo(BearerTokenError.INVALID_REQUEST);
    assertThat(response.contains(TokenFilterHelper.DPOP_NONCE_HEADER_NAME)).isFalse();
  }

  @Test
  public void invalidToken() throws Exception {
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(HttpHeader.AUTHORIZATION, "bearer invalid");
    var response = server.getResponse(request);
    assertThat(response.getStatus()).isEqualTo(BearerTokenError.INVALID_TOKEN.getHTTPStatusCode());
    var wwwAuthenticate = response.get(HttpHeader.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isNotNull();
    assertThat(BearerTokenError.parse(wwwAuthenticate)).isEqualTo(BearerTokenError.INVALID_TOKEN);
    assertThat(response.contains(TokenFilterHelper.DPOP_NONCE_HEADER_NAME)).isFalse();
  }

  @Test
  public void validToken() throws Exception {
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(HttpHeader.AUTHORIZATION, client.get().toAuthorizationHeader());
    var response = server.getResponse(request);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContent()).isEqualTo("service-account-app");
    assertThat(response.contains(TokenFilterHelper.DPOP_NONCE_HEADER_NAME)).isFalse();
  }

  @Test
  public void validTokenInSecondAuthorizationHeader() throws Exception {
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.add(
        HttpHeader.AUTHORIZATION, server.getClientAuthentication().toHTTPAuthorizationHeader());
    request.add(HttpHeader.AUTHORIZATION, client.get().toAuthorizationHeader());
    var response = server.getResponse(request);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContent()).isEqualTo("service-account-app");
    assertThat(response.contains(TokenFilterHelper.DPOP_NONCE_HEADER_NAME)).isFalse();
  }

  @Test
  public void revokedButCachedToken() throws Exception {
    var token = client.get();
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(HttpHeader.AUTHORIZATION, token.toAuthorizationHeader());
    var response = server.getResponse(request);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContent()).isEqualTo("service-account-app");
    assertThat(response.contains(TokenFilterHelper.DPOP_NONCE_HEADER_NAME)).isFalse();

    client.revoke(token);

    request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(HttpHeader.AUTHORIZATION, token.toAuthorizationHeader());
    response = server.getResponse(request);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContent()).isEqualTo("service-account-app");
    assertThat(response.contains(TokenFilterHelper.DPOP_NONCE_HEADER_NAME)).isFalse();
  }
}
