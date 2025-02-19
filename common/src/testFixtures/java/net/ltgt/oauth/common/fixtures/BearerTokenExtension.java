package net.ltgt.oauth.common.fixtures;

import static java.util.Objects.requireNonNull;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.TokenRevocationRequest;
import com.nimbusds.oauth2.sdk.as.ReadOnlyAuthorizationServerMetadata;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.uber.nullaway.annotations.Initializer;
import java.io.IOException;
import java.util.LinkedHashSet;
import java.util.Set;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterResolutionException;

public class BearerTokenExtension implements BeforeEachCallback, AfterEachCallback {
  private final ReadOnlyAuthorizationServerMetadata authorizationServerMetadata;
  private final ClientSecretBasic clientAuthentication;

  private Set<BearerAccessToken> tokens;

  public BearerTokenExtension() {
    authorizationServerMetadata = Helpers.loadAuthorizationServerMetadata();
    clientAuthentication =
        new ClientSecretBasic(
            new ClientID(requireNonNull(System.getProperty("test.app.clientId"))),
            new Secret(requireNonNull(System.getProperty("test.app.clientSecret"))));
  }

  @Initializer
  @Override
  public void beforeEach(ExtensionContext context) throws Exception {
    tokens = new LinkedHashSet<>();
  }

  @Override
  public void afterEach(ExtensionContext context) throws Exception {
    for (var token : tokens) {
      revoke(token);
    }
  }

  public BearerAccessToken get(String... scope) {
    var requestBuilder =
        new TokenRequest.Builder(
            authorizationServerMetadata.getTokenEndpointURI(),
            clientAuthentication,
            new ClientCredentialsGrant());
    if (scope.length > 0) {
      requestBuilder.scope(new Scope(scope));
    }
    AccessTokenResponse response;
    try {
      response =
          TokenResponse.parse(requestBuilder.build().toHTTPRequest().send()).toSuccessResponse();
    } catch (IOException | ParseException | ClassCastException e) {
      throw new ParameterResolutionException("Error retrieving bearer token", e);
    }
    var token = response.getTokens().getBearerAccessToken();
    tokens.add(token);
    return token;
  }

  public void revoke(BearerAccessToken token) throws IOException, ParseException {
    new TokenRevocationRequest(
            authorizationServerMetadata.getRevocationEndpointURI(), clientAuthentication, token)
        .toHTTPRequest()
        .send()
        .ensureStatusCode(200);
    tokens.remove(token);
  }
}
