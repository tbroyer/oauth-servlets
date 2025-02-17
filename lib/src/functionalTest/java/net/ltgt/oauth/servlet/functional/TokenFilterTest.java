package net.ltgt.oauth.servlet.functional;

import static com.google.common.truth.Truth.assertThat;

import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Optional;
import net.ltgt.oauth.servlet.TokenPrincipal;
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
    var request = HttpRequest.newBuilder().GET().uri(server.getURI("/")).build();
    var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    assertThat(response.statusCode()).isEqualTo(200);
    assertThat(response.body()).isEqualTo("null");
  }

  @Test
  public void badAuthScheme() throws Exception {
    var request =
        HttpRequest.newBuilder()
            .GET()
            .uri(server.getURI("/"))
            .header("Authorization", server.getClientAuthentication().toHTTPAuthorizationHeader())
            .build();
    var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    assertThat(response.statusCode()).isEqualTo(200);
    assertThat(response.body()).isEqualTo("null");
  }

  @Test
  public void badAuthScheme2() throws Exception {
    var request =
        HttpRequest.newBuilder()
            .GET()
            .uri(server.getURI("/"))
            .header("Authorization", "bearertoken")
            .build();
    var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    assertThat(response.statusCode()).isEqualTo(200);
    assertThat(response.body()).isEqualTo("null");
  }

  @Test
  public void missingToken() throws Exception {
    var request =
        HttpRequest.newBuilder()
            .GET()
            .uri(server.getURI("/"))
            .header("Authorization", "bearer")
            .build();
    var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    assertThat(response.statusCode())
        .isEqualTo(BearerTokenError.INVALID_REQUEST.getHTTPStatusCode());
    var wwwAuthenticate = response.headers().firstValue("www-authenticate");
    assertThat(wwwAuthenticate).isPresent();
    assertThat(BearerTokenError.parse(wwwAuthenticate.get()))
        .isEqualTo(BearerTokenError.INVALID_REQUEST);
  }

  @Test
  public void missingToken2() throws Exception {
    var request =
        HttpRequest.newBuilder()
            .GET()
            .uri(server.getURI("/"))
            .header("Authorization", "bearer ")
            .build();
    var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    assertThat(response.statusCode())
        .isEqualTo(BearerTokenError.INVALID_REQUEST.getHTTPStatusCode());
    var wwwAuthenticate = response.headers().firstValue("www-authenticate");
    assertThat(wwwAuthenticate).isPresent();
    assertThat(BearerTokenError.parse(wwwAuthenticate.get()))
        .isEqualTo(BearerTokenError.INVALID_REQUEST);
  }

  @Test
  public void invalidToken() throws Exception {
    var request =
        HttpRequest.newBuilder()
            .GET()
            .uri(server.getURI("/"))
            .header("Authorization", "bearer invalid")
            .build();
    var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    assertThat(response.statusCode()).isEqualTo(BearerTokenError.INVALID_TOKEN.getHTTPStatusCode());
    var wwwAuthenticate = response.headers().firstValue("www-authenticate");
    assertThat(wwwAuthenticate).isPresent();
    assertThat(BearerTokenError.parse(wwwAuthenticate.get()))
        .isEqualTo(BearerTokenError.INVALID_TOKEN);
  }

  @Test
  public void validToken() throws Exception {
    var request =
        HttpRequest.newBuilder()
            .GET()
            .uri(server.getURI("/"))
            .header("Authorization", client.get().toAuthorizationHeader())
            .build();
    var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    assertThat(response.statusCode()).isEqualTo(200);
    assertThat(response.body()).isEqualTo("service-account-app");
  }

  @Test
  public void revokedButCachedToken() throws Exception {
    var token = client.get();
    var request =
        HttpRequest.newBuilder()
            .GET()
            .uri(server.getURI("/"))
            .header("Authorization", token.toAuthorizationHeader())
            .build();
    var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    assertThat(response.statusCode()).isEqualTo(200);
    assertThat(response.body()).isEqualTo("service-account-app");

    client.revoke(token);

    request =
        HttpRequest.newBuilder()
            .GET()
            .uri(server.getURI("/"))
            .header("Authorization", token.toAuthorizationHeader())
            .build();
    response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    assertThat(response.statusCode()).isEqualTo(200);
    assertThat(response.body()).isEqualTo("service-account-app");
  }
}
