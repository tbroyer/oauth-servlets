package net.ltgt.oauth.rs.functional;

import static java.util.Objects.requireNonNull;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.oauth2.sdk.as.ReadOnlyAuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import jakarta.ws.rs.core.SecurityContext;
import java.io.IOException;
import java.security.Principal;
import java.util.function.Consumer;
import net.ltgt.oauth.common.KeycloakTokenPrincipal;
import net.ltgt.oauth.common.TokenIntrospector;
import net.ltgt.oauth.common.TokenPrincipalProvider;
import net.ltgt.oauth.common.fixtures.Helpers;
import net.ltgt.oauth.rs.TokenFilter;
import org.jboss.resteasy.mock.MockDispatcherFactory;
import org.jboss.resteasy.spi.Dispatcher;
import org.jboss.resteasy.spi.HttpRequest;
import org.jboss.resteasy.spi.HttpResponse;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;

public class WebServerExtension implements BeforeEachCallback, AfterEachCallback {
  private final ReadOnlyAuthorizationServerMetadata authorizationServerMetadata;
  private final ClientSecretBasic clientAuthentication;
  private final Dispatcher dispatcher;

  public ReadOnlyAuthorizationServerMetadata getAuthorizationServerMetadata() {
    return authorizationServerMetadata;
  }

  public ClientSecretBasic getClientAuthentication() {
    return clientAuthentication;
  }

  public void invoke(HttpRequest request, HttpResponse response) throws IOException {
    dispatcher.invoke(request, response);
  }

  public WebServerExtension(Consumer<Dispatcher> configure) {
    authorizationServerMetadata = Helpers.loadAuthorizationServerMetadata();
    clientAuthentication =
        new ClientSecretBasic(
            new ClientID(requireNonNull(System.getProperty("test.api.clientId"))),
            new Secret(requireNonNull(System.getProperty("test.api.clientSecret"))));
    dispatcher = MockDispatcherFactory.createDispatcher();
    dispatcher
        .getDefaultContextObjects()
        .put(
            SecurityContext.class,
            new SecurityContext() {
              @Override
              public @Nullable Principal getUserPrincipal() {
                return null;
              }

              @Override
              public boolean isUserInRole(String role) {
                return false;
              }

              @Override
              public boolean isSecure() {
                return false;
              }

              @Override
              public @Nullable String getAuthenticationScheme() {
                return null;
              }
            });
    dispatcher
        .getProviderFactory()
        .property(TokenPrincipalProvider.CONTEXT_ATTRIBUTE_NAME, KeycloakTokenPrincipal.PROVIDER);
    dispatcher.getProviderFactory().register(TokenFilter.class);
    configure.accept(dispatcher);
  }

  @Override
  public void beforeEach(ExtensionContext context) throws Exception {
    dispatcher
        .getProviderFactory()
        .property(
            TokenIntrospector.CONTEXT_ATTRIBUTE_NAME,
            new TokenIntrospector(
                authorizationServerMetadata, clientAuthentication, Caffeine.newBuilder()));
  }

  @Override
  public void afterEach(ExtensionContext context) throws Exception {
    ((TokenIntrospector)
            dispatcher.getProviderFactory().getProperty(TokenIntrospector.CONTEXT_ATTRIBUTE_NAME))
        .invalidateAll();
  }
}
