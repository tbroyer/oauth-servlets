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

import com.google.errorprone.annotations.RestrictedApi;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.oauth2.sdk.token.TokenSchemeError;
import com.nimbusds.openid.connect.sdk.Nonce;
import java.io.IOException;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import org.jspecify.annotations.Nullable;

/** Internal interface used by {@code TokenFilter}. */
public interface TokenFilterHelper {
  String X509_CERTIFICATE_REQUEST_ATTRIBUTE_NAME = "jakarta.servlet.request.X509Certificate";

  String DPOP_HEADER_NAME = "DPoP";
  String DPOP_NONCE_HEADER_NAME = "DPoP-Nonce";

  @RestrictedApi(explanation = "Internal API", allowedOnPath = ".*/java/net/ltgt/oauth/.*")
  List<TokenSchemeError> getUnauthorizedErrors();

  @RestrictedApi(explanation = "Internal API", allowedOnPath = ".*/java/net/ltgt/oauth/.*")
  @Nullable Nonce getDPoPNonce();

  @RestrictedApi(explanation = "Internal API", allowedOnPath = ".*/java/net/ltgt/oauth/.*")
  List<TokenSchemeError> adaptError(String authenticationScheme, BearerTokenError error);

  @RestrictedApi(explanation = "Internal API", allowedOnPath = ".*/java/net/ltgt/oauth/.*")
  <E extends Exception> void filter(
      String method,
      URI uri,
      List<String> authorizations,
      List<String> dpopProofs,
      @Nullable X509Certificate clientCertificate,
      FilterChain<E> chain)
      throws IOException, E;

  /** Internal interface used by {@code TokenFilter}. */
  interface FilterChain<E extends Exception> {
    void continueChain(@Nullable Nonce dpopNonce) throws IOException, E;

    void continueChain(
        String authenticationScheme, TokenPrincipal tokenPrincipal, @Nullable Nonce dpopNonce)
        throws IOException, E;

    void sendError(
        List<TokenSchemeError> errors,
        @Nullable Nonce dpopNonce,
        String message,
        @Nullable Throwable cause)
        throws IOException, E;

    void sendError(int statusCode, String message, @Nullable Throwable cause) throws IOException, E;
  }
}
