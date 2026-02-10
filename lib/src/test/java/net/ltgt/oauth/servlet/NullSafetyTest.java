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
package net.ltgt.oauth.servlet;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.google.common.testing.NullPointerTester;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import java.lang.reflect.Modifier;
import java.net.URI;
import net.ltgt.oauth.common.TokenIntrospector;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.Test;

public class NullSafetyTest {
  private <T> void testPublicApi(NullPointerTester tester, Class<T> cls, @Nullable T instance) {
    tester.testStaticMethods(cls, NullPointerTester.Visibility.PROTECTED);
    if (!Modifier.isAbstract(cls.getModifiers())) {
      tester.testConstructors(cls, NullPointerTester.Visibility.PROTECTED);
    }
    if (instance != null) {
      tester.testInstanceMethods(instance, NullPointerTester.Visibility.PROTECTED);
    }
  }

  @Test
  void testFilters() {
    var tester =
        new NullPointerTester()
            .setDefault(
                TokenIntrospector.class,
                new TokenIntrospector(
                    URI.create("https://example.com/introspect"),
                    new ClientSecretBasic(new ClientID("client_id"), new Secret("client_sectet")),
                    Caffeine.newBuilder()));
    testPublicApi(tester, TokenFilter.class, null);
    testPublicApi(tester, AbstractAuthorizationFilter.class, null);
    testPublicApi(tester, IsAuthenticatedFilter.class, null);
    testPublicApi(tester, HasRoleFilter.class, null);
    testPublicApi(tester, HasScopeFilter.class, null);
  }
}
