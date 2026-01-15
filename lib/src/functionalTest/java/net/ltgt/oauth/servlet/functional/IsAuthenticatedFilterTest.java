package net.ltgt.oauth.servlet.functional;

import static com.google.common.truth.Truth.assertThat;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.oauth2.sdk.token.DPoPTokenError;
import com.nimbusds.openid.connect.sdk.Nonce;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import net.ltgt.oauth.common.DPoPTokenFilterHelper;
import net.ltgt.oauth.common.TokenFilterHelper;
import net.ltgt.oauth.common.TokenFilterHelperFactory;
import net.ltgt.oauth.common.TokenPrincipal;
import net.ltgt.oauth.common.fixtures.DPoPTokenExtension;
import net.ltgt.oauth.servlet.IsAuthenticatedFilter;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpTester;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

public class IsAuthenticatedFilterTest {
  private static final Set<JWSAlgorithm> ALGS = Set.of(JWSAlgorithm.ES256, JWSAlgorithm.PS256);
  private static final Nonce OLD_NONCE = new Nonce();
  private static final Nonce CURRENT_NONCE = new Nonce();

  @RegisterExtension
  public WebServerExtension server =
      new WebServerExtension(
          contextHandler -> {
            contextHandler.setAttribute(
                TokenFilterHelperFactory.CONTEXT_ATTRIBUTE_NAME,
                new DPoPTokenFilterHelper.Factory(
                    ALGS, null, () -> List.of(CURRENT_NONCE, OLD_NONCE)));
            contextHandler.addFilter(IsAuthenticatedFilter.class, "/*", null);
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

  @RegisterExtension public DPoPTokenExtension client = new DPoPTokenExtension(JWSAlgorithm.ES256);

  @Test
  public void noAuthentication() throws Exception {
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    var response = server.getResponse(request);
    assertThat(response.getStatus()).isEqualTo(DPoPTokenError.MISSING_TOKEN.getHTTPStatusCode());
    var wwwAuthenticate = response.get(HttpHeader.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isNotNull();
    assertThat(DPoPTokenError.parse(wwwAuthenticate))
        .isEqualTo(DPoPTokenError.MISSING_TOKEN.setJWSAlgorithms(ALGS));
    assertThat(response.getValuesList(TokenFilterHelper.DPOP_NONCE_HEADER_NAME))
        .containsExactly(CURRENT_NONCE.getValue());
  }

  @Test
  public void validToken() throws Exception {
    var token = client.get();
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(HttpHeader.AUTHORIZATION, token.toAuthorizationHeader());
    request.put(
        TokenFilterHelper.DPOP_HEADER_NAME,
        client.createDPoPJWT("GET", server.getURI("/"), token, CURRENT_NONCE).serialize());
    var response = server.getResponse(request);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContent()).isEqualTo("service-account-app");
    assertThat(response.contains(TokenFilterHelper.DPOP_NONCE_HEADER_NAME)).isFalse();
  }
}
