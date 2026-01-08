package net.ltgt.oauth.common;

import static java.util.Objects.requireNonNull;
import static net.ltgt.oauth.common.Utils.checkMTLSBoundToken;
import static net.ltgt.oauth.common.Utils.isDPoPToken;
import static net.ltgt.oauth.common.Utils.matchesAuthenticationScheme;
import static net.ltgt.oauth.common.Utils.parseDPoPProof;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
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
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
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
 * Authenticates the request using either a DPoP token or a Bearer token, and introspecting it, if
 * provided in the request.
 */
public class DPoPOrBearerTokenFilterHelper implements TokenFilterHelper {
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
      return new DPoPOrBearerTokenFilterHelper(
          requireNonNull(tokenIntrospector),
          requireNonNull(tokenPrincipalProvider),
          acceptedJWSAlgs,
          verifier);
    }
  }

  private final TokenIntrospector tokenIntrospector;
  private final TokenPrincipalProvider tokenPrincipalProvider;
  private final Set<JWSAlgorithm> acceptedJWSAlgs;
  private final DPoPProtectedResourceRequestVerifier verifier;

  private DPoPOrBearerTokenFilterHelper(
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
    return List.of(
        DPoPTokenError.MISSING_TOKEN.setJWSAlgorithms(acceptedJWSAlgs),
        BearerTokenError.MISSING_TOKEN);
  }

  @Override
  public List<TokenSchemeError> adaptError(String authenticationScheme, BearerTokenError error) {
    if (authenticationScheme.equals(AccessTokenType.DPOP.getValue())) {
      return List.of(
          new DPoPTokenError(
              error.getCode(),
              error.getDescription(),
              error.getHTTPStatusCode(),
              error.getURI(),
              error.getRealm(),
              error.getScope(),
              acceptedJWSAlgs),
          BearerTokenError.MISSING_TOKEN);
    }
    assert authenticationScheme.equals(AccessTokenType.BEARER.getValue());
    return List.of(error, DPoPTokenError.MISSING_TOKEN.setJWSAlgorithms(acceptedJWSAlgs));
  }

  @Override
  public <E extends Exception> void filter(
      String method,
      URI uri,
      List<String> authorizations,
      List<String> dpopProofs,
      @Nullable X509Certificate clientCertificate,
      FilterChain<E> chain)
      throws IOException, E {
    var dpopAuthorization =
        authorizations.stream()
            .filter(authorization -> matchesAuthenticationScheme("dpop", authorization))
            .findFirst()
            .orElse(null);
    var bearerAuthorization =
        authorizations.stream()
            .filter(authorization -> matchesAuthenticationScheme("bearer", authorization))
            .findFirst()
            .orElse(null);
    if (dpopAuthorization != null) {
      handleDPoPToken(
          method,
          uri,
          dpopAuthorization,
          bearerAuthorization,
          dpopProofs,
          clientCertificate,
          chain);
      return;
    }
    if (bearerAuthorization != null) {
      handleBearerToken(bearerAuthorization, clientCertificate, chain);
      return;
    }
    // dpopAuthorization == null && bearerAuthorization == null
    chain.continueChain();
  }

  private <E extends Exception> void handleDPoPToken(
      String method,
      URI uri,
      String dpopAuthorization,
      @Nullable String bearerAuthorization,
      List<String> dpopProofs,
      @Nullable X509Certificate clientCertificate,
      FilterChain<E> chain)
      throws IOException, E {
    DPoPAccessToken token;
    try {
      token = DPoPAccessToken.parse(dpopAuthorization);
    } catch (ParseException e) {
      if (DPoPTokenError.MISSING_TOKEN.equals(e.getErrorObject())) {
        // this should never happen, but just in case
        token = null;
      } else {
        sendError(
            chain,
            ((DPoPTokenError) e.getErrorObject()),
            "Error parsing the Authorization header",
            e);
        return;
      }
    }
    if (token == null) {
      chain.continueChain();
      return;
    }
    // https://www.rfc-editor.org/rfc/rfc9449#section-7.2
    if (bearerAuthorization != null) {
      BearerAccessToken bearerToken;
      try {
        bearerToken = BearerAccessToken.parse(bearerAuthorization);
      } catch (ParseException e) {
        // ignore malformed header
        bearerToken = null;
      }
      if (bearerToken != null) {
        chain.sendError(
            List.of(
                DPoPTokenError.INVALID_REQUEST
                    .setJWSAlgorithms(acceptedJWSAlgs)
                    .setDescription("Multiple methods used to include access token"),
                BearerTokenError.INVALID_REQUEST.setDescription(
                    "Multiple methods used to include access token")),
            "Multiple methods used to include access token",
            null);
        return;
      }
    }

    // https://www.rfc-editor.org/rfc/rfc9449#section-4.3
    var dpopProof =
        parseDPoPProof(
            dpopProofs,
            (message, cause) ->
                sendError(chain, DPoPTokenError.INVALID_DPOP_PROOF, message, cause));
    if (dpopProof == null) {
      return;
    }

    TokenIntrospectionSuccessResponse introspectionResponse;
    try {
      introspectionResponse = tokenIntrospector.introspect(token);
    } catch (CompletionException e) {
      chain.sendError(HTTPResponse.SC_SERVER_ERROR, "Error introspecting token", e.getCause());
      return;
    }
    if (introspectionResponse == null || !isDPoPToken(introspectionResponse)) {
      sendError(chain, DPoPTokenError.INVALID_TOKEN, "Invalid token", null);
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
      // ath and jkt are checked as part of Section 4.3, but section 7.1 shows an invalid_token
      // we use invalid_dpop_proof following Section 4.3 (invalid_token wouldn't be wrong though)
      // cf. https://mailarchive.ietf.org/arch/msg/oauth/g5mF_rJbscAXraQ5izxhXnvZp-o/
      sendError(chain, DPoPTokenError.INVALID_DPOP_PROOF, "Invalid DPoP proof", e);
      return;
    }

    String errorMessage =
        checkMTLSBoundToken(
            introspectionResponse.getX509CertificateConfirmation(), clientCertificate);
    if (errorMessage != null) {
      sendError(chain, DPoPTokenError.INVALID_TOKEN, errorMessage, null);
      return;
    }

    var tokenPrincipal = tokenPrincipalProvider.getTokenPrincipal(introspectionResponse);
    if (tokenPrincipal != null) {
      chain.continueChain(AccessTokenType.DPOP.getValue(), tokenPrincipal);
    } else {
      chain.continueChain();
    }
  }

  private <E extends Exception> void handleBearerToken(
      String bearerAuthorization, @Nullable X509Certificate clientCertificate, FilterChain<E> chain)
      throws IOException, E {
    BearerAccessToken token;
    try {
      token = BearerAccessToken.parse(bearerAuthorization);
    } catch (ParseException e) {
      if (BearerTokenError.MISSING_TOKEN.equals(e.getErrorObject())) {
        // this should never happen, but just in case
        token = null;
      } else {
        sendError(
            chain,
            ((BearerTokenError) e.getErrorObject()),
            "Error parsing the Authorization header",
            e);
        return;
      }
    }
    if (token == null) {
      chain.continueChain();
      return;
    }

    TokenIntrospectionSuccessResponse introspectionResponse;
    try {
      introspectionResponse = tokenIntrospector.introspect(token);
    } catch (CompletionException e) {
      chain.sendError(HTTPResponse.SC_SERVER_ERROR, "Error introspecting token", e.getCause());
      return;
    }
    if (introspectionResponse == null) {
      sendError(chain, BearerTokenError.INVALID_TOKEN, "Invalid token", null);
      return;
    }

    if (introspectionResponse.getJWKThumbprintConfirmation() != null) {
      sendError(
          chain,
          BearerTokenError.INVALID_TOKEN,
          "Downgraded usage of a DPoP-bound access token",
          null);
      return;
    }

    String errorMessage =
        checkMTLSBoundToken(
            introspectionResponse.getX509CertificateConfirmation(), clientCertificate);
    if (errorMessage != null) {
      sendError(chain, BearerTokenError.INVALID_TOKEN, errorMessage, null);
      return;
    }

    var tokenPrincipal = tokenPrincipalProvider.getTokenPrincipal(introspectionResponse);
    if (tokenPrincipal != null) {
      chain.continueChain(AccessTokenType.BEARER.getValue(), tokenPrincipal);
    } else {
      chain.continueChain();
    }
  }

  private <E extends Exception> void sendError(
      FilterChain<E> chain, DPoPTokenError error, String message, @Nullable Throwable cause)
      throws IOException, E {
    chain.sendError(
        List.of(error.setJWSAlgorithms(acceptedJWSAlgs), BearerTokenError.MISSING_TOKEN),
        message,
        cause);
  }

  private <E extends Exception> void sendError(
      FilterChain<E> chain, BearerTokenError error, String message, @Nullable Throwable cause)
      throws IOException, E {
    chain.sendError(
        List.of(error, DPoPTokenError.MISSING_TOKEN.setJWSAlgorithms(acceptedJWSAlgs)),
        message,
        cause);
  }
}
