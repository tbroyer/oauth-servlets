package net.ltgt.oauth.servlet.functional;

import static java.util.Objects.requireNonNull;

import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.as.AuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.as.ReadOnlyAuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.id.Issuer;
import java.io.IOException;
import org.opentest4j.TestAbortedException;

public class Helpers {

  public static ReadOnlyAuthorizationServerMetadata loadAuthorizationServerMetadata() {
    String issuer = requireNonNull(System.getProperty("test.issuer"));
    try {
      return AuthorizationServerMetadata.resolve(new Issuer(issuer));
    } catch (GeneralException | IOException e) {
      throw new TestAbortedException(
          "Can't load authorization server metadata. Is Keycloak started and configured?", e);
    }
  }

  private Helpers() {}
}
