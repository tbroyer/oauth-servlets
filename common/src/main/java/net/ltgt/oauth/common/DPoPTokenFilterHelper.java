package net.ltgt.oauth.common;

import static java.util.Objects.requireNonNull;
import static java.util.Objects.requireNonNullElse;
import static net.ltgt.oauth.common.Utils.checkMTLSBoundToken;
import static net.ltgt.oauth.common.Utils.matchesAuthenticationScheme;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenIntrospectionSuccessResponse;
import com.nimbusds.oauth2.sdk.dpop.verifiers.AccessTokenValidationException;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPIssuer;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPProofUse;
import com.nimbusds.oauth2.sdk.dpop.verifiers.DPoPProtectedResourceRequestVerifier;
import com.nimbusds.oauth2.sdk.dpop.verifiers.InvalidDPoPProofException;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import com.nimbusds.oauth2.sdk.token.DPoPAccessToken;
import com.nimbusds.oauth2.sdk.token.DPoPTokenError;
import com.nimbusds.oauth2.sdk.token.TokenSchemeError;
import com.nimbusds.oauth2.sdk.util.singleuse.SingleUseChecker;
import java.io.IOException;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CompletionException;
import org.jspecify.annotations.Nullable;

/**
 * Authenticates the request using a DPoP token and introspecting it, if provided in the request.
 */
public class DPoPTokenFilterHelper implements TokenFilterHelper {

  public static class Factory implements TokenFilterHelperFactory {

    public static final long DEFAULT_MAX_CLOCK_SKEW_SECONDS =
        DefaultJWTClaimsVerifier.DEFAULT_MAX_CLOCK_SKEW_SECONDS;
    public static final long DEFAULT_MAX_AGE_SECONDS = DEFAULT_MAX_CLOCK_SKEW_SECONDS;

    private final Set<JWSAlgorithm> acceptedJWSAlgs;
    private final DPoPProtectedResourceRequestVerifier verifier;

    /**
     * Constructs a factory with the given accepted JWS algorithms, an optional single use checker,
     * and the default max clock skew and max age.
     */
    public Factory(
        Set<JWSAlgorithm> acceptedJWSAlgs,
        @Nullable SingleUseChecker<DPoPProofUse> singleUseChecker) {
      this(
          acceptedJWSAlgs,
          DEFAULT_MAX_CLOCK_SKEW_SECONDS,
          DEFAULT_MAX_AGE_SECONDS,
          singleUseChecker);
    }

    /**
     * Constructs a factory with the given accepted JWS algorithms, max clock skew, max age, and an
     * optional single use checker.
     */
    public Factory(
        Set<JWSAlgorithm> acceptedJWSAlgs,
        long maxClockSkewSeconds,
        long maxAgeSeconds,
        @Nullable SingleUseChecker<DPoPProofUse> singleUseChecker) {
      this.acceptedJWSAlgs = acceptedJWSAlgs = Set.copyOf(acceptedJWSAlgs);
      this.verifier =
          new DPoPProtectedResourceRequestVerifier(
              acceptedJWSAlgs, maxClockSkewSeconds, maxAgeSeconds, singleUseChecker);
    }

    @Override
    public TokenFilterHelper create(
        TokenIntrospector tokenIntrospector, TokenPrincipalProvider tokenPrincipalProvider) {
      return new DPoPTokenFilterHelper(
          requireNonNull(tokenIntrospector),
          requireNonNull(tokenPrincipalProvider),
          acceptedJWSAlgs,
          verifier);
    }
  }

  private final TokenIntrospector tokenIntrospector;
  private final TokenPrincipalProvider tokenPrincipalProvider;
  private final DPoPProtectedResourceRequestVerifier verifier;
  private final Set<JWSAlgorithm> acceptedJWSAlgs;

  private DPoPTokenFilterHelper(
      TokenIntrospector tokenIntrospector,
      TokenPrincipalProvider tokenPrincipalProvider,
      Set<JWSAlgorithm> acceptedJWSAlgs,
      DPoPProtectedResourceRequestVerifier verifier) {
    this.tokenIntrospector = tokenIntrospector;
    this.tokenPrincipalProvider = tokenPrincipalProvider;
    this.acceptedJWSAlgs = acceptedJWSAlgs;
    this.verifier = verifier;
  }

  @Override
  public List<TokenSchemeError> getUnauthorizedErrors() {
    return List.of(DPoPTokenError.MISSING_TOKEN.setJWSAlgorithms(acceptedJWSAlgs));
  }

  @Override
  public List<TokenSchemeError> adaptError(String authenticationScheme, BearerTokenError error) {
    assert authenticationScheme.equals(AccessTokenType.DPOP.getValue());
    return List.of(
        new DPoPTokenError(
            error.getCode(),
            error.getDescription(),
            error.getHTTPStatusCode(),
            error.getURI(),
            error.getRealm(),
            error.getScope(),
            acceptedJWSAlgs));
  }

  @Override
  public <E extends Exception> void filter(
      String method,
      URI uri,
      List<String> authorizations,
      List<String> dpopProofs,
      @Nullable X509Certificate clientCertificate,
      TokenFilterHelper.FilterChain<E> chain)
      throws IOException, E {
    if (authorizations.isEmpty()) {
      chain.continueChain();
      return;
    }
    var authorization = authorizations.getFirst();
    if (!matchesAuthenticationScheme("dpop", authorization)) {
      chain.continueChain();
      return;
    }

    DPoPAccessToken token;
    try {
      token = DPoPAccessToken.parse(authorization);
    } catch (ParseException e) {
      if (DPoPTokenError.MISSING_TOKEN.equals(e.getErrorObject())) {
        // this should never happen, but just in case
        token = null;
      } else {
        chain.sendError(
            List.of(((DPoPTokenError) e.getErrorObject()).setJWSAlgorithms(acceptedJWSAlgs)),
            "Error parsing the Authorization header",
            e);
        return;
      }
    }

    if (token == null) {
      chain.continueChain();
      return;
    }

    // https://www.rfc-editor.org/rfc/rfc9449#section-4.3
    if (dpopProofs.isEmpty()) {
      chain.sendError(
          List.of(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(acceptedJWSAlgs)),
          "Missing DPoP proof",
          null);
      return;
    } else if (dpopProofs.size() > 1) {
      chain.sendError(
          List.of(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(acceptedJWSAlgs)),
          "Too many DPoP proofs",
          null);
      return;
    }
    SignedJWT dpopProof;
    try {
      dpopProof = SignedJWT.parse(dpopProofs.getFirst());
    } catch (java.text.ParseException e) {
      chain.sendError(
          List.of(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(acceptedJWSAlgs)),
          "Error parsing the DPoP proof",
          e);
      return;
    }

    TokenIntrospectionSuccessResponse introspectionResponse;
    try {
      introspectionResponse = tokenIntrospector.introspect(token);
    } catch (CompletionException e) {
      chain.sendError(HTTPResponse.SC_SERVER_ERROR, "Error introspecting token", e.getCause());
      return;
    }
    if (introspectionResponse == null
        // Not a DPoP token (token_type is present and not DPoP)
        || !AccessTokenType.DPOP.equals(
            requireNonNullElse(introspectionResponse.getTokenType(), AccessTokenType.DPOP))
        // Not a DPoP token (missing cnf.jkt in introspection response)
        || introspectionResponse.getJWKThumbprintConfirmation() == null) {
      chain.sendError(
          List.of(DPoPTokenError.INVALID_TOKEN.setJWSAlgorithms(acceptedJWSAlgs)),
          "Invalid token",
          null);
      return;
    }
    try {
      // XXX: should Resource Server-Provided Nonces be supported?
      verifier.verify(
          method,
          uri,
          new DPoPIssuer(introspectionResponse.getClientID()),
          dpopProof,
          token,
          introspectionResponse.getJWKThumbprintConfirmation(),
          null);
    } catch (AccessTokenValidationException | InvalidDPoPProofException | JOSEException e) {
      chain.sendError(
          List.of(DPoPTokenError.INVALID_DPOP_PROOF.setJWSAlgorithms(acceptedJWSAlgs)),
          "Invalid DPoP proof",
          e);
      return;
    }

    String errorMessage =
        checkMTLSBoundToken(
            introspectionResponse.getX509CertificateConfirmation(), clientCertificate);
    if (errorMessage != null) {
      chain.sendError(List.of(BearerTokenError.INVALID_TOKEN), errorMessage, null);
      return;
    }

    var tokenPrincipal = tokenPrincipalProvider.getTokenPrincipal(introspectionResponse);
    if (tokenPrincipal != null) {
      chain.continueChain(AccessTokenType.DPOP.getValue(), tokenPrincipal);
    } else {
      chain.continueChain();
    }
  }
}
