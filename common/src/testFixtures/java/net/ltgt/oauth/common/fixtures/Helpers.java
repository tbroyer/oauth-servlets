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
