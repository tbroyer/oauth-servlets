package net.ltgt.oauth.rs.functional;

import static com.google.common.truth.Truth.assertThat;

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
import org.jboss.resteasy.mock.MockHttpRequest;
import org.jboss.resteasy.mock.MockHttpResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class TokenFilterTest {
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
            dispatcher.getRegistry().addPerRequestResource(TestResource.class);
          });

  @RegisterExtension public BearerTokenExtension client = new BearerTokenExtension();

  @Test
  public void noAuthentication() throws Exception {
    var request = MockHttpRequest.get("/");
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).isEqualTo("null");
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
  }

  @Test
  public void badAuthScheme2() throws Exception {
    var request = MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, "bearertoken");
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).isEqualTo("null");
  }

  @Test
  public void missingToken() throws Exception {
    var request = MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, "bearer");
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus())
        .isEqualTo(BearerTokenError.INVALID_REQUEST.getHTTPStatusCode());
    var wwwAuthenticate = response.getOutputHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isInstanceOf(String.class);
    assertThat(BearerTokenError.parse((String) wwwAuthenticate))
        .isEqualTo(BearerTokenError.INVALID_REQUEST);
  }

  @Test
  public void missingToken2() throws Exception {
    var request = MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, "bearer ");
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus())
        .isEqualTo(BearerTokenError.INVALID_REQUEST.getHTTPStatusCode());
    var wwwAuthenticate = response.getOutputHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isInstanceOf(String.class);
    assertThat(BearerTokenError.parse((String) wwwAuthenticate))
        .isEqualTo(BearerTokenError.INVALID_REQUEST);
  }

  @Test
  public void invalidToken() throws Exception {
    var request = MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, "bearer invalid");
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(BearerTokenError.INVALID_TOKEN.getHTTPStatusCode());
    var wwwAuthenticate = response.getOutputHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isInstanceOf(String.class);
    assertThat(BearerTokenError.parse((String) wwwAuthenticate))
        .isEqualTo(BearerTokenError.INVALID_TOKEN);
  }

  @Test
  public void validToken() throws Exception {
    var request =
        MockHttpRequest.get("/")
            .header(HttpHeaders.AUTHORIZATION, client.get().toAuthorizationHeader());
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).isEqualTo("service-account-app");
  }

  @Test
  public void validTokenInSecondAuthorizationHeader() throws Exception {
    var request =
        MockHttpRequest.get("/")
            .header(
                HttpHeaders.AUTHORIZATION,
                server.getClientAuthentication().toHTTPAuthorizationHeader())
            .header(HttpHeaders.AUTHORIZATION, client.get().toAuthorizationHeader());
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).isEqualTo("service-account-app");
  }

  @Test
  public void revokedButCachedToken() throws Exception {
    var token = client.get();
    var request =
        MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, token.toAuthorizationHeader());
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).isEqualTo("service-account-app");

    client.revoke(token);

    request =
        MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, token.toAuthorizationHeader());
    response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).isEqualTo("service-account-app");
  }
}
