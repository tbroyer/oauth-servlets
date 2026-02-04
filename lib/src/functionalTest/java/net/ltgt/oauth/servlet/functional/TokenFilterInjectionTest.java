package net.ltgt.oauth.servlet.functional;

import static com.google.common.truth.Truth.assertThat;
import static java.util.Objects.requireNonNull;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import net.ltgt.oauth.common.KeycloakTokenPrincipal;
import net.ltgt.oauth.common.TokenIntrospector;
import net.ltgt.oauth.common.TokenPrincipal;
import net.ltgt.oauth.common.fixtures.BearerTokenExtension;
import net.ltgt.oauth.common.fixtures.Helpers;
import net.ltgt.oauth.servlet.TokenFilter;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpTester;
import org.eclipse.jetty.server.LocalConnector;
import org.eclipse.jetty.server.Server;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class TokenFilterInjectionTest {

  @RegisterExtension public BearerTokenExtension client = new BearerTokenExtension();

  private Server server;
  private LocalConnector connector;
  private TokenIntrospector tokenIntrospector;

  @BeforeEach
  void setup() throws Exception {
    server = new Server();
    connector = new LocalConnector(server);
    server.addConnector(connector);
    var contextHandler = new ServletContextHandler();
    server.setHandler(contextHandler);

    var authorizationServerMetadata = Helpers.loadAuthorizationServerMetadata();
    var clientAuthentication =
        new ClientSecretBasic(
            new ClientID(requireNonNull(System.getProperty("test.api.clientId"))),
            new Secret(requireNonNull(System.getProperty("test.api.clientSecret"))));
    tokenIntrospector =
        new TokenIntrospector(
            authorizationServerMetadata, clientAuthentication, Caffeine.newBuilder());

    // Typical usage would be using an injection framework
    contextHandler.addFilter(
        new TokenFilter(tokenIntrospector, KeycloakTokenPrincipal.PROVIDER), "/*", null);

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

    server.start();
  }

  @AfterEach
  void tearDown() throws Exception {
    server.stop();
    tokenIntrospector.invalidateAll();
  }

  @Test
  void validToken() throws Exception {
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(HttpHeader.AUTHORIZATION, client.get("test1").toAuthorizationHeader());
    request.put(HttpHeader.HOST, "localhost");
    var response = HttpTester.parseResponse(connector.getResponse(request.generate()));
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContent()).isEqualTo("service-account-app");
  }
}
