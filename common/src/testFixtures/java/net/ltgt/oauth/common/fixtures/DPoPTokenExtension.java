package net.ltgt.oauth.common.fixtures;

import static java.util.Objects.requireNonNull;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.SignedJWT;
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
import com.nimbusds.oauth2.sdk.dpop.DPoPProofFactory;
import com.nimbusds.oauth2.sdk.dpop.DefaultDPoPProofFactory;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.openid.connect.sdk.Nonce;
import com.uber.nullaway.annotations.Initializer;
import java.io.IOException;
import java.net.URI;
import java.util.LinkedHashSet;
import java.util.Set;
import org.jspecify.annotations.Nullable;
import org.junit.jupiter.api.extension.AfterEachCallback;
import org.junit.jupiter.api.extension.BeforeEachCallback;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.ParameterResolutionException;

public class DPoPTokenExtension implements BeforeEachCallback, AfterEachCallback {
  private final ReadOnlyAuthorizationServerMetadata authorizationServerMetadata;
  private final ClientSecretBasic clientAuthentication;
  private final JWSAlgorithm alg;

  private Set<DPoPAccessToken> tokens;
  private JWK jwk;
  private DPoPProofFactory proofFactory;

  public DPoPTokenExtension(JWSAlgorithm alg) {
    authorizationServerMetadata = Helpers.loadAuthorizationServerMetadata();
    clientAuthentication =
        new ClientSecretBasic(
            new ClientID(requireNonNull(System.getProperty("test.app.clientId"))),
            new Secret(requireNonNull(System.getProperty("test.app.clientSecret"))));
    this.alg = alg;
  }

  @Initializer
  @Override
  public void beforeEach(ExtensionContext context) throws Exception {
    tokens = new LinkedHashSet<DPoPAccessToken>();
    jwk = new ECKeyGenerator(Curve.P_256).generate();
    proofFactory = new DefaultDPoPProofFactory(jwk, alg);
  }

  @Override
  public void afterEach(ExtensionContext context) throws Exception {
    for (DPoPAccessToken token : Set.copyOf(tokens)) {
      revoke(token);
    }
  }

  public DPoPAccessToken get(String... scope) throws JOSEException {
    var requestBuilder =
        new TokenRequest.Builder(
            authorizationServerMetadata.getTokenEndpointURI(),
            clientAuthentication,
            new ClientCredentialsGrant());
    if (scope.length > 0) {
      requestBuilder.scope(new Scope(scope));
    }
    var request = requestBuilder.build().toHTTPRequest();
    var dpopProof = proofFactory.createDPoPJWT(request.getMethod().name(), request.getURI());
    request.setDPoP(dpopProof);
    AccessTokenResponse response;
    try {
      response = TokenResponse.parse(request.send()).toSuccessResponse();
    } catch (IOException | ParseException | ClassCastException e) {
      throw new ParameterResolutionException("Error retrieving bearer token", e);
    }
    var token = response.getTokens().getDPoPAccessToken();
    tokens.add(token);
    return token;
  }

  public void revoke(DPoPAccessToken token) throws IOException, ParseException {
    new TokenRevocationRequest(
            authorizationServerMetadata.getRevocationEndpointURI(), clientAuthentication, token)
        .toHTTPRequest()
        .send()
        .ensureStatusCode(200);
    tokens.remove(token);
  }

  public SignedJWT createDPoPJWT(
      String method, URI uri, @Nullable AccessToken token, @Nullable Nonce nonce)
      throws JOSEException {
    return proofFactory.createDPoPJWT(method, uri, token, nonce);
  }
}
