package net.ltgt.oauth.rs.functional;

import static com.google.common.truth.Truth.assertThat;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.SecurityContext;
import java.util.Optional;
import net.ltgt.oauth.common.TokenPrincipal;
import net.ltgt.oauth.common.fixtures.BearerTokenExtension;
import net.ltgt.oauth.rs.HasScope;
import net.ltgt.oauth.rs.HasScopeFeature;
import org.jboss.resteasy.mock.MockHttpRequest;
import org.jboss.resteasy.mock.MockHttpResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class HasScopeFilterTest {
  @Path("/")
  @HasScope("test1")
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
            dispatcher.getProviderFactory().register(HasScopeFeature.class);
            dispatcher.getRegistry().addPerRequestResource(TestResource.class);
          });

  @RegisterExtension public BearerTokenExtension client = new BearerTokenExtension();

  @Test
  public void noAuthentication() throws Exception {
    var request = MockHttpRequest.get("/");
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(BearerTokenError.MISSING_TOKEN.getHTTPStatusCode());
    var wwwAuthenticate = response.getOutputHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isInstanceOf(String.class);
    assertThat(BearerTokenError.parse((String) wwwAuthenticate))
        .isEqualTo(BearerTokenError.MISSING_TOKEN);
  }

  @Test
  public void insufficientScope() throws Exception {
    var request =
        MockHttpRequest.get("/")
            .header(HttpHeaders.AUTHORIZATION, client.get("test2").toAuthorizationHeader());
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus())
        .isEqualTo(BearerTokenError.INSUFFICIENT_SCOPE.getHTTPStatusCode());
    var wwwAuthenticate = response.getOutputHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isInstanceOf(String.class);
    assertThat(BearerTokenError.parse((String) wwwAuthenticate))
        .isEqualTo(BearerTokenError.INSUFFICIENT_SCOPE.setScope(new Scope("test1")));
  }

  @Test
  public void validToken() throws Exception {
    var request =
        MockHttpRequest.get("/")
            .header(HttpHeaders.AUTHORIZATION, client.get("test1").toAuthorizationHeader());
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).isEqualTo("service-account-app");
  }

  @Test
  public void validToken2() throws Exception {
    var request =
        MockHttpRequest.get("/")
            .header(
                HttpHeaders.AUTHORIZATION, client.get("test1", "test2").toAuthorizationHeader());
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).isEqualTo("service-account-app");
  }
}
