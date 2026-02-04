package net.ltgt.oauth.rs.functional;

import static com.google.common.truth.Truth.assertThat;
import static java.util.Objects.requireNonNull;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.SecurityContext;
import java.security.Principal;
import java.util.Optional;
import net.ltgt.oauth.common.TokenFilterHelper;
import net.ltgt.oauth.common.TokenIntrospector;
import net.ltgt.oauth.common.TokenPrincipal;
import net.ltgt.oauth.common.fixtures.BearerTokenExtension;
import net.ltgt.oauth.common.fixtures.Helpers;
import net.ltgt.oauth.rs.TokenFilter;
import org.jboss.resteasy.mock.MockDispatcherFactory;
import org.jboss.resteasy.mock.MockHttpRequest;
import org.jboss.resteasy.mock.MockHttpResponse;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class TokenFilterSubclassTest {
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

  public static class SimpleTokenFilter extends TokenFilter {
    private final TokenIntrospector tokenIntrospector;

    public SimpleTokenFilter(TokenIntrospector tokenIntrospector) {
      this.tokenIntrospector = tokenIntrospector;
    }

    @Override
    protected TokenIntrospector getTokenIntrospector() {
      return tokenIntrospector;
    }
  }

  @RegisterExtension public BearerTokenExtension client = new BearerTokenExtension();

  @Test
  public void validToken() throws Exception {
    var authorizationServerMetadata = Helpers.loadAuthorizationServerMetadata();
    var clientAuthentication =
        new ClientSecretBasic(
            new ClientID(requireNonNull(System.getProperty("test.api.clientId"))),
            new Secret(requireNonNull(System.getProperty("test.api.clientSecret"))));
    var server = MockDispatcherFactory.createDispatcher();
    server
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
    var tokenIntrospector =
        new TokenIntrospector(
            authorizationServerMetadata, clientAuthentication, Caffeine.newBuilder());
    // Typical usage would be a subclass where the TokenIntrospector (at least) is injected through
    // an injection framework, with the getters overridden to return the injected value; and
    // possibly with deeper integration into JAX-RS to have the injection done on the fly rather
    // than using a singleton.
    // We only want to test that we don't introduce regressions here though, so make it simple.
    server.getProviderFactory().register(new SimpleTokenFilter(tokenIntrospector));
    server.getRegistry().addPerRequestResource(TestResource.class);

    var request =
        MockHttpRequest.get("/")
            .header(HttpHeaders.AUTHORIZATION, client.get().toAuthorizationHeader());
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).isEqualTo("service-account-app");
    assertThat(response.getOutputHeaders())
        .doesNotContainKey(TokenFilterHelper.DPOP_NONCE_HEADER_NAME);
  }
}
