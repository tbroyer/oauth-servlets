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
package net.ltgt.oauth.common;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.google.common.testing.NullPointerTester;
import com.google.common.testing.NullPointerTester.Visibility;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import java.lang.reflect.Modifier;
import java.net.URI;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

public class NullSafetyTest {
  private <T> void testPublicApi(NullPointerTester tester, Class<T> cls, @Nullable T instance) {
    tester.testStaticMethods(cls, Visibility.PROTECTED);
    if (!Modifier.isAbstract(cls.getModifiers())) {
      tester.testConstructors(cls, Visibility.PROTECTED);
    }
    if (instance != null) {
      tester.testInstanceMethods(instance, Visibility.PROTECTED);
    }
  }

  @Test
  void testTokenIntrospector() {
    var introspectionEndpointURI = URI.create("https://example.com/introspect");
    var clientAuthentication =
        new ClientSecretBasic(new ClientID("client_id"), new Secret("client_secret"));
    var tester =
        new NullPointerTester()
            .setDefault(URI.class, introspectionEndpointURI)
            .setDefault(ClientAuthentication.class, clientAuthentication)
            .setDefault(Caffeine.class, Caffeine.newBuilder());
    testPublicApi(
        tester,
        TokenIntrospector.class,
        new TokenIntrospector(
            introspectionEndpointURI,
            clientAuthentication,
            Caffeine.newBuilder(),
            httpRequest ->
                new TokenIntrospectionSuccessResponse.Builder(false).build().toHTTPResponse()));
    // XXX: put in its own test method? It's just an interface for now
    testPublicApi(tester, ClientAuthenticationSupplier.class, null);
  }

  @Test
  void testTokenTypeSupport() {
    var tester = new NullPointerTester();
    testPublicApi(tester, TokenTypeSupport.class, null);
  }

  @Test
  void testTokenPrincipal() throws Exception {
    var tokenInfo = new TokenIntrospectionSuccessResponse.Builder(true).build();
    var tester =
        new NullPointerTester()
            .setDefault(Caffeine.class, Caffeine.newBuilder())
            // hasRole might not throw a long as it returns false for a null role
            .ignore(SimpleTokenPrincipal.class.getMethod("hasRole", String.class))
            .ignore(KeycloakTokenPrincipal.class.getMethod("hasRole", String.class))
            // hasScope might not throw a long as it returns false for a null role
            .ignore(SimpleTokenPrincipal.class.getMethod("hasScope", String.class))
            .ignore(SimpleTokenPrincipal.class.getMethod("hasScope", Scope.Value.class))
            .ignore(KeycloakTokenPrincipal.class.getMethod("hasScope", String.class))
            .ignore(KeycloakTokenPrincipal.class.getMethod("hasScope", Scope.Value.class));
    testPublicApi(tester, TokenPrincipalProvider.class, null);
    testPublicApi(tester, TokenPrincipal.class, null);
    testPublicApi(tester, SimpleTokenPrincipal.class, new SimpleTokenPrincipal(tokenInfo));
    testPublicApi(tester, KeycloakTokenPrincipal.class, new KeycloakTokenPrincipal(tokenInfo));
    testPublicApi(
        tester,
        CachedTokenPrincipalProvider.class,
        CachedTokenPrincipalProvider.newInstance(
            SimpleTokenPrincipal.PROVIDER, Caffeine.newBuilder()));
  }

  @Test
  void testCaffeineDPoPSingleUseChecker() {
    var tester =
        new NullPointerTester() //
            .setDefault(Caffeine.class, Caffeine.newBuilder());
    testPublicApi(tester, CaffeineDPoPSingleUseChecker.class, new CaffeineDPoPSingleUseChecker());
  }
}
