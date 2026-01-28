package net.ltgt.oauth.rs.functional;

import static com.google.common.truth.Truth.assertThat;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.token.DPoPTokenError;
import com.nimbusds.openid.connect.sdk.Nonce;
import jakarta.ws.rs.GET;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.SecurityContext;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import net.ltgt.oauth.common.TokenFilterHelper;
import net.ltgt.oauth.common.TokenPrincipal;
import net.ltgt.oauth.common.TokenTypeSupport;
import net.ltgt.oauth.common.fixtures.DPoPTokenExtension;
import net.ltgt.oauth.rs.IsAuthenticated;
import net.ltgt.oauth.rs.IsAuthenticatedFilter;
import org.jboss.resteasy.mock.MockHttpRequest;
import org.jboss.resteasy.mock.MockHttpResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class IsAuthenticatedFilterTest {
  private static final Set<JWSAlgorithm> ALGS = Set.of(JWSAlgorithm.ES256, JWSAlgorithm.PS256);
  private static final Nonce OLD_NONCE = new Nonce();
  private static final Nonce CURRENT_NONCE = new Nonce();

  @Path("/")
  @IsAuthenticated
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
            dispatcher
                .getProviderFactory()
                .property(
                    TokenTypeSupport.CONTEXT_ATTRIBUTE_NAME,
                    TokenTypeSupport.dpop(ALGS, null, () -> List.of(CURRENT_NONCE, OLD_NONCE)));
            dispatcher.getProviderFactory().register(IsAuthenticatedFilter.class);
            dispatcher.getRegistry().addPerRequestResource(TestResource.class);
          });

  @RegisterExtension public DPoPTokenExtension client = new DPoPTokenExtension(JWSAlgorithm.ES256);

  @Test
  public void noAuthentication() throws Exception {
    var request = MockHttpRequest.get("/");
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(DPoPTokenError.MISSING_TOKEN.getHTTPStatusCode());
    var wwwAuthenticate = response.getOutputHeaders().getFirst(HttpHeaders.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isInstanceOf(String.class);
    assertThat(DPoPTokenError.parse((String) wwwAuthenticate))
        .isEqualTo(DPoPTokenError.MISSING_TOKEN.setJWSAlgorithms(ALGS));
    assertThat(
            response
                .getOutputHeaders()
                .getOrDefault(TokenFilterHelper.DPOP_NONCE_HEADER_NAME, List.of()))
        .containsExactly(CURRENT_NONCE.getValue());
  }

  @Test
  public void validToken() throws Exception {
    var token = client.get();
    var request =
        MockHttpRequest.get("/").header(HttpHeaders.AUTHORIZATION, token.toAuthorizationHeader());
    request.header(
        TokenFilterHelper.DPOP_HEADER_NAME,
        client
            .createDPoPJWT(
                request.getHttpMethod(), request.getUri().getAbsolutePath(), token, CURRENT_NONCE)
            .serialize());
    var response = new MockHttpResponse();
    server.invoke(request, response);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContentAsString()).isEqualTo("service-account-app");
    assertThat(response.getOutputHeaders())
        .doesNotContainKey(TokenFilterHelper.DPOP_NONCE_HEADER_NAME);
  }
}
