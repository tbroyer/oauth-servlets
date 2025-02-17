package net.ltgt.oauth.servlet.functional;

import static com.google.common.truth.Truth.assertThat;

import com.nimbusds.oauth2.sdk.Scope;
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
import net.ltgt.oauth.servlet.HasScopeFilter;
import net.ltgt.oauth.servlet.TokenPrincipal;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class HasScopeFilterTest {
  @RegisterExtension
  public WebServerExtension server =
      new WebServerExtension(
          contextHandler -> {
            contextHandler
                .addFilter(HasScopeFilter.class, "/*", null)
                .setInitParameter(HasScopeFilter.SCOPE, "test1");
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
    assertThat(response.statusCode()).isEqualTo(BearerTokenError.MISSING_TOKEN.getHTTPStatusCode());
    var wwwAuthenticate = response.headers().firstValue("www-authenticate");
    assertThat(wwwAuthenticate).isPresent();
    assertThat(BearerTokenError.parse(wwwAuthenticate.get()))
        .isEqualTo(BearerTokenError.MISSING_TOKEN);
  }

  @Test
  public void insufficientScope() throws Exception {
    var request =
        HttpRequest.newBuilder()
            .GET()
            .uri(server.getURI("/"))
            .header("Authorization", client.get("test2").toAuthorizationHeader())
            .build();
    var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    assertThat(response.statusCode())
        .isEqualTo(BearerTokenError.INSUFFICIENT_SCOPE.getHTTPStatusCode());
    var wwwAuthenticate = response.headers().firstValue("www-authenticate");
    assertThat(wwwAuthenticate).isPresent();
    assertThat(BearerTokenError.parse(wwwAuthenticate.get()))
        .isEqualTo(BearerTokenError.INSUFFICIENT_SCOPE.setScope(new Scope("test1")));
  }

  @Test
  public void validToken() throws Exception {
    var request =
        HttpRequest.newBuilder()
            .GET()
            .uri(server.getURI("/"))
            .header("Authorization", client.get("test1").toAuthorizationHeader())
            .build();
    var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    assertThat(response.statusCode()).isEqualTo(200);
    assertThat(response.body()).isEqualTo("service-account-app");
  }

  @Test
  public void validToken2() throws Exception {
    var request =
        HttpRequest.newBuilder()
            .GET()
            .uri(server.getURI("/"))
            .header("Authorization", client.get("test1", "test2").toAuthorizationHeader())
            .build();
    var response = HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    assertThat(response.statusCode()).isEqualTo(200);
    assertThat(response.body()).isEqualTo("service-account-app");
  }
}
