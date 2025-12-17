package net.ltgt.oauth.servlet.functional;

import static java.util.Objects.requireNonNull;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.oauth2.sdk.as.ReadOnlyAuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import jakarta.servlet.ServletContextEvent;
import jakarta.servlet.ServletContextListener;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.function.Consumer;
import net.ltgt.oauth.common.KeycloakTokenPrincipal;
import net.ltgt.oauth.common.TokenIntrospector;
import net.ltgt.oauth.common.TokenPrincipalProvider;
import net.ltgt.oauth.common.fixtures.Helpers;
import net.ltgt.oauth.servlet.TokenFilter;
import org.eclipse.jetty.ee10.servlet.ServletContextHandler;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpTester;
import org.eclipse.jetty.server.LocalConnector;
import org.eclipse.jetty.server.Server;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

public class WebServerExtension implements BeforeEachCallback, AfterEachCallback {
  private final ReadOnlyAuthorizationServerMetadata authorizationServerMetadata;
  private final ClientSecretBasic clientAuthentication;
  private final Server server;
  private final LocalConnector connector;

  public ReadOnlyAuthorizationServerMetadata getAuthorizationServerMetadata() {
    return authorizationServerMetadata;
  }

  public ClientSecretBasic getClientAuthentication() {
    return clientAuthentication;
  }

  public URI getURI(String path) throws URISyntaxException {
    return new URI("http", "localhost", path, null);
  }

  public HttpTester.Response getResponse(HttpTester.Request request) throws Exception {
    request.put(HttpHeader.HOST, "localhost");
    return HttpTester.parseResponse(connector.getResponse(request.generate()));
  }

  public WebServerExtension(Consumer<ServletContextHandler> configure) {
    authorizationServerMetadata = Helpers.loadAuthorizationServerMetadata();
    clientAuthentication =
        new ClientSecretBasic(
            new ClientID(requireNonNull(System.getProperty("test.api.clientId"))),
            new Secret(requireNonNull(System.getProperty("test.api.clientSecret"))));
    server = new Server();
    connector = new LocalConnector(server);
    server.addConnector(connector);
    var contextHandler = new ServletContextHandler();
    server.setHandler(contextHandler);

    contextHandler.addEventListener(
        new ServletContextListener() {
          @Override
          public void contextInitialized(ServletContextEvent sce) {
            sce.getServletContext()
                .setAttribute(
                    TokenIntrospector.CONTEXT_ATTRIBUTE_NAME,
                    new TokenIntrospector(
                        authorizationServerMetadata, clientAuthentication, Caffeine.newBuilder()));
          }

          @Override
          public void contextDestroyed(ServletContextEvent sce) {
            ((TokenIntrospector)
                    sce.getServletContext().getAttribute(TokenIntrospector.CONTEXT_ATTRIBUTE_NAME))
                .invalidateAll();
          }
        });
    contextHandler.setAttribute(
        TokenPrincipalProvider.CONTEXT_ATTRIBUTE_NAME, KeycloakTokenPrincipal.PROVIDER);

    contextHandler.addFilter(TokenFilter.class, "/*", null);

    configure.accept(contextHandler);
  }

  @Override
  public void beforeEach(ExtensionContext context) throws Exception {
    server.start();
  }

  @Override
  public void afterEach(ExtensionContext context) throws Exception {
    server.stop();
  }
}
