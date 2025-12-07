package net.ltgt.oauth.common;

import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;

/**
 * Returns a {@link ClientAuthentication} instance to be used to authenticate the application when
 * making HTTP requests to the authorization server.
 */
@FunctionalInterface
public interface ClientAuthenticationSupplier {
  /**
   * Called on each request to the authorization server that needs the application to be
   * authenticated.
   *
   * <p>The returned value can be always the same <i>static</i> value (shared between all
   * authenticated requests), for instance for {@link com.nimbusds.oauth2.sdk.auth.ClientSecretBasic
   * client_secret_basic}, {@link com.nimbusds.oauth2.sdk.auth.ClientSecretPost client_secret_post},
   * {@link com.nimbusds.oauth2.sdk.auth.SelfSignedTLSClientAuthentication
   * self_signed_tls_client_auth} or {@link com.nimbusds.oauth2.sdk.auth.PKITLSClientAuthentication
   * tls_client_auth}, or a different instance at every call, e.g. for JWT-based authentication such
   * as {@link com.nimbusds.oauth2.sdk.auth.ClientSecretJWT client_secret_jwt} or {@link
   * com.nimbusds.oauth2.sdk.auth.PrivateKeyJWT private_key_jwt}.
   */
  ClientAuthentication getClientAuthentication();
}
