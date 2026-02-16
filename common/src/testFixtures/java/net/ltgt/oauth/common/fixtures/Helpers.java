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
package net.ltgt.oauth.common.fixtures;

import static java.util.Objects.requireNonNull;
import static org.junit.jupiter.api.Assertions.fail;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.as.ReadOnlyAuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.id.Issuer;
import java.io.IOException;

public class Helpers {

  public static ReadOnlyAuthorizationServerMetadata loadAuthorizationServerMetadata() {
    String issuer = requireNonNull(System.getProperty("test.issuer"));
    try {
      return AuthorizationServerMetadata.resolve(new Issuer(issuer));
    } catch (GeneralException | IOException e) {
      return fail(
          "Can't load authorization server metadata. Is Keycloak started and configured?", e);
    }
  }

  private Helpers() {}
}
