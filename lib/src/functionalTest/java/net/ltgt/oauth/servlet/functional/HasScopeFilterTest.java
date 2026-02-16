/*
 * Copyright © 2026 Thomas Broyer
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.ltgt.oauth.servlet.functional;

import static com.google.common.truth.Truth.assertThat;

import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import net.ltgt.oauth.common.TokenPrincipal;
import net.ltgt.oauth.common.fixtures.BearerTokenExtension;
import net.ltgt.oauth.servlet.HasScopeFilter;
import org.eclipse.jetty.http.HttpHeader;
import org.eclipse.jetty.http.HttpTester;
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
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    var response = server.getResponse(request);
    assertThat(response.getStatus()).isEqualTo(BearerTokenError.MISSING_TOKEN.getHTTPStatusCode());
    var wwwAuthenticate = response.get(HttpHeader.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isNotNull();
    assertThat(BearerTokenError.parse(wwwAuthenticate)).isEqualTo(BearerTokenError.MISSING_TOKEN);
  }

  @Test
  public void insufficientScope() throws Exception {
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(HttpHeader.AUTHORIZATION, client.get("test2").toAuthorizationHeader());
    var response = server.getResponse(request);
    assertThat(response.getStatus())
        .isEqualTo(BearerTokenError.INSUFFICIENT_SCOPE.getHTTPStatusCode());
    var wwwAuthenticate = response.get(HttpHeader.WWW_AUTHENTICATE);
    assertThat(wwwAuthenticate).isNotNull();
    assertThat(BearerTokenError.parse(wwwAuthenticate))
        .isEqualTo(BearerTokenError.INSUFFICIENT_SCOPE.setScope(new Scope("test1")));
  }

  @Test
  public void validToken() throws Exception {
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(HttpHeader.AUTHORIZATION, client.get("test1").toAuthorizationHeader());
    var response = server.getResponse(request);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContent()).isEqualTo("service-account-app");
  }

  @Test
  public void validToken2() throws Exception {
    var request = HttpTester.newRequest();
    request.setMethod("GET");
    request.setURI("/");
    request.put(HttpHeader.AUTHORIZATION, client.get("test1", "test2").toAuthorizationHeader());
    var response = server.getResponse(request);
    assertThat(response.getStatus()).isEqualTo(200);
    assertThat(response.getContent()).isEqualTo("service-account-app");
  }
}
