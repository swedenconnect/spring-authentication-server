/*
 * Copyright 2026 Sweden Connect
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
package se.swedenconnect.spring.authnserver.oidc.token;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.pkce.CodeChallenge;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeVerifier;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.openid.connect.sdk.OIDCTokenResponse;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;
import com.nimbusds.openid.connect.sdk.token.OIDCTokens;

import se.swedenconnect.spring.authnserver.audit.AuditRequester;
import se.swedenconnect.spring.authnserver.audit.AuditStage;
import se.swedenconnect.spring.authnserver.audit.AuthnEventPublisher;
import se.swedenconnect.spring.authnserver.audit.FlowCorrelation;
import se.swedenconnect.spring.authnserver.audit.events.AuthnErrorResponseEvent;
import se.swedenconnect.spring.authnserver.audit.events.AuthnSuccessResponseEvent;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.oidc.attributes.DeliveredClaims;
import se.swedenconnect.spring.authnserver.oidc.audit.OidcAuditData;
import se.swedenconnect.spring.authnserver.oidc.error.OidcUnrecoverableError;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * Processes token requests, as OpenID Connect Core, Section 3.1.3, and RFC 6749, Section 4.1.3, describe.
 * <p>
 * The client is authenticated first, see {@link ClientAuthenticator}. Only the {@code authorization_code} grant is
 * supported. The code must have been issued to the client, must not have expired and must not have been used before.
 * A code that is used a second time is rejected, and the access token that was issued for it is revoked, as RFC 6749,
 * Section 4.1.2, says. {@code redirect_uri} must be identical to the one of the authentication request, and when the
 * request had a PKCE code challenge, {@code code_verifier} must be present and match it (RFC 7636, Section 4.6). A
 * verifier sent without a challenge is rejected.
 * </p>
 * <p>
 * A successful request gets an opaque access token and the ID token, see {@link IdTokenBuilder}. No refresh token is
 * issued. Every response carries {@code Cache-Control: no-store}.
 * </p>
 * <p>
 * The request is audited under the correlation ID that the code is bound to. A successful request is audited as an
 * {@code authn_success_response} event and a failed one as an {@code authn_error_response} event.
 * </p>
 *
 * @author Martin Lindström
 */
public class TokenRequestProcessor {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(TokenRequestProcessor.class);

  /** The default access token lifetime, 5 minutes. */
  public static final Duration DEFAULT_ACCESS_TOKEN_LIFETIME = Duration.ofMinutes(5);

  /** Authenticates the client. */
  private final ClientAuthenticator clientAuthenticator;

  /** Keeps the authorization codes. */
  private final AuthorizationCodeStore codeStore;

  /** Keeps the access tokens. */
  private final AccessTokenStore accessTokenStore;

  /** Builds the ID tokens. */
  private final IdTokenBuilder idTokenBuilder;

  /** The access token lifetime. */
  private Duration accessTokenLifetime = DEFAULT_ACCESS_TOKEN_LIFETIME;

  /** Whether access tokens may only be used once. */
  private boolean singleUseAccessTokens = true;

  /** Publishes the audit events. */
  private AuthnEventPublisher eventPublisher = AuthnEventPublisher.noop();

  /**
   * Constructor.
   *
   * @param clientAuthenticator authenticates the client
   * @param codeStore keeps the authorization codes
   * @param accessTokenStore keeps the access tokens
   * @param idTokenBuilder builds the ID tokens
   */
  public TokenRequestProcessor(final @NonNull ClientAuthenticator clientAuthenticator,
      final @NonNull AuthorizationCodeStore codeStore, final @NonNull AccessTokenStore accessTokenStore,
      final @NonNull IdTokenBuilder idTokenBuilder) {
    this.clientAuthenticator = Objects.requireNonNull(clientAuthenticator, "clientAuthenticator must not be null");
    this.codeStore = Objects.requireNonNull(codeStore, "codeStore must not be null");
    this.accessTokenStore = Objects.requireNonNull(accessTokenStore, "accessTokenStore must not be null");
    this.idTokenBuilder = Objects.requireNonNull(idTokenBuilder, "idTokenBuilder must not be null");
  }

  /**
   * Processes a token request.
   *
   * @param httpRequest the request
   * @return the token response or the token error response
   */
  public @NonNull HTTPResponse process(final @NonNull HTTPRequest httpRequest) {
    final AuditState audit = new AuditState();
    HTTPResponse response;
    try {
      response = this.processRequest(httpRequest, audit).toHTTPResponse();
    }
    catch (final TokenErrorException e) {
      response = new TokenErrorResponse(e.getError()).toHTTPResponse();
      final AuditRequester requester = audit.requester != null
          ? audit.requester
          : AuditRequester.named(AuthenticationProtocol.OIDC, getNamedClientId(httpRequest));
      this.eventPublisher.publish(new AuthnErrorResponseEvent(requester,
          OidcAuditData.httpErrorResponse(response.getStatusCode()), AuditStage.TOKEN, e.getError().getCode(),
          e.getError().getDescription()));
    }
    response.setCacheControl("no-store");
    response.setPragma("no-cache");
    return response;
  }

  /**
   * Processes a token request.
   *
   * @param httpRequest the request
   * @param audit where the requester is recorded for the audit
   * @return the token response
   * @throws TokenErrorException if the request fails
   */
  private @NonNull OIDCTokenResponse processRequest(final @NonNull HTTPRequest httpRequest,
      final @NonNull AuditState audit)
      throws TokenErrorException {

    if (!HTTPRequest.Method.POST.equals(httpRequest.getMethod())) {
      throw new TokenErrorException(OAuth2Error.INVALID_REQUEST, "The token endpoint only accepts POST");
    }
    final RequesterRecord client = this.clientAuthenticator.authenticate(httpRequest);
    audit.requester = AuditRequester.of(client, true);
    final String clientId = client.getIdentifier();
    final String logString = "requester: 'OIDC:%s'".formatted(clientId);

    final Map<String, List<String>> parameters;
    try {
      parameters = httpRequest.getBodyAsFormParameters();
    }
    catch (final com.nimbusds.oauth2.sdk.ParseException e) {
      throw invalidRequest("The token request is not form encoded", logString);
    }
    final String grantType = getParameter(parameters, "grant_type");
    if (grantType == null) {
      throw invalidRequest("Missing grant_type", logString);
    }
    if (!GrantType.AUTHORIZATION_CODE.getValue().equals(grantType)) {
      log.info("Unsupported grant_type '{}' [{}]", grantType, logString);
      throw new TokenErrorException(OAuth2Error.UNSUPPORTED_GRANT_TYPE,
          "Only the authorization_code grant is supported");
    }
    final String codeValue = getParameter(parameters, "code");
    if (codeValue == null) {
      throw invalidRequest("Missing code", logString);
    }

    // Redeem the code ...
    //
    final AuthorizationCodeStore.Redemption redemption = this.codeStore.redeem(codeValue);
    if (redemption == null) {
      throw invalidGrant("The code is not known or has expired", logString);
    }
    final AuthorizationCodeData code = redemption.code();
    FlowCorrelation.join(code.correlationId());
    if (redemption.replay()) {
      log.warn("An authorization code was used a second time - its access token is revoked [{}]", logString);
      if (redemption.accessToken() != null) {
        this.accessTokenStore.revoke(redemption.accessToken());
      }
      throw new TokenErrorException(OAuth2Error.INVALID_GRANT, "The code has already been used");
    }
    if (!clientId.equals(code.clientId())) {
      throw invalidGrant("The code was issued to another client", logString);
    }
    if (!code.redirectUri().equals(getParameter(parameters, "redirect_uri"))) {
      throw invalidGrant("The redirect_uri does not match the authentication request", logString);
    }
    checkCodeVerifier(code, getParameter(parameters, "code_verifier"), logString);

    // Issue the tokens ...
    //
    final Instant now = Instant.now();
    final OIDCClientMetadata metadata = client.getProtocolMetadata(OIDCClientMetadata.class);
    final String idToken;
    try {
      idToken = this.idTokenBuilder.build(code, metadata, now);
    }
    catch (final UnrecoverableErrorException e) {
      if (e.getError() == OidcUnrecoverableError.INVALID_CLIENT_CONFIGURATION) {
        throw new TokenErrorException(OAuth2Error.INVALID_CLIENT, e.getMessage(), e);
      }
      throw new TokenErrorException(OAuth2Error.SERVER_ERROR, "The ID token could not be issued", e);
    }
    final Scope scope = new Scope(code.scopes().toArray(String[]::new));
    final BearerAccessToken accessToken =
        new BearerAccessToken(32, this.accessTokenLifetime.toSeconds(), scope);
    this.accessTokenStore.save(new AccessTokenData(accessToken.getValue(), clientId, code.subject(), code.scopes(),
        code.userInfoClaims(), now, now.plus(this.accessTokenLifetime), this.singleUseAccessTokens,
        FlowCorrelation.current()));
    this.codeStore.registerAccessToken(codeValue, accessToken.getValue());

    this.eventPublisher.publish(new AuthnSuccessResponseEvent(audit.requester,
        OidcAuditData.tokenResponse(code, metadata.getIDTokenJWEAlg() != null),
        OidcAuditData.claims(DeliveredClaims.parse(code.idTokenClaims()))));
    log.debug("Issued ID token and access token [{}]", logString);
    return new OIDCTokenResponse(new OIDCTokens(idToken, accessToken, null));
  }

  /**
   * Checks the PKCE code verifier.
   *
   * @param code the code
   * @param verifier the code verifier of the request, or {@code null}
   * @param logString the log string
   * @throws TokenErrorException with {@code invalid_grant} if the verifier is missing, does not match or was sent
   *     without a challenge
   */
  private static void checkCodeVerifier(final @NonNull AuthorizationCodeData code, final @Nullable String verifier,
      final @NonNull String logString) throws TokenErrorException {
    if (code.codeChallenge() == null) {
      if (verifier != null) {
        throw invalidGrant("A code_verifier was sent, but the authentication request had no code_challenge",
            logString);
      }
      return;
    }
    if (verifier == null) {
      throw invalidGrant("Missing code_verifier", logString);
    }
    final CodeVerifier codeVerifier;
    try {
      codeVerifier = new CodeVerifier(verifier);
    }
    catch (final IllegalArgumentException e) {
      throw invalidGrant("Invalid code_verifier", logString);
    }
    final CodeChallengeMethod method = CodeChallengeMethod.parse(
        Objects.requireNonNullElse(code.codeChallengeMethod(), CodeChallengeMethod.S256.getValue()));
    if (!CodeChallenge.compute(method, codeVerifier).getValue().equals(code.codeChallenge())) {
      throw invalidGrant("The code_verifier does not match the code_challenge", logString);
    }
  }

  /**
   * Gets a parameter that may occur only once.
   *
   * @param parameters the parameters
   * @param name the name
   * @return the value, or {@code null} if it is missing or occurs more than once
   */
  private static @Nullable String getParameter(final @NonNull Map<String, List<String>> parameters,
      final @NonNull String name) {
    final List<String> values = parameters.get(name);
    return values != null && values.size() == 1 && !values.getFirst().isBlank() ? values.getFirst() : null;
  }

  /**
   * Creates the exception for an invalid request, and logs it.
   *
   * @param description the description
   * @param logString the log string
   * @return a {@link TokenErrorException}
   */
  private static @NonNull TokenErrorException invalidRequest(final @NonNull String description,
      final @NonNull String logString) {
    log.info("Invalid token request - {} [{}]", description, logString);
    return new TokenErrorException(OAuth2Error.INVALID_REQUEST, description);
  }

  /**
   * Creates the exception for an invalid grant, and logs it.
   *
   * @param description the description
   * @param logString the log string
   * @return a {@link TokenErrorException}
   */
  private static @NonNull TokenErrorException invalidGrant(final @NonNull String description,
      final @NonNull String logString) {
    log.info("Invalid grant - {} [{}]", description, logString);
    return new TokenErrorException(OAuth2Error.INVALID_GRANT, description);
  }

  /**
   * Assigns the publisher of the audit events. The default publishes nothing.
   *
   * @param eventPublisher the event publisher
   */
  public void setEventPublisher(final @NonNull AuthnEventPublisher eventPublisher) {
    this.eventPublisher = Objects.requireNonNull(eventPublisher, "eventPublisher must not be null");
  }

  /**
   * Gets the {@code client_id} that a token request names, for the audit of a request whose client could not be
   * authenticated.
   *
   * @param httpRequest the request
   * @return the {@code client_id}, or {@code null} if the request names none
   */
  private static @Nullable String getNamedClientId(final @NonNull HTTPRequest httpRequest) {
    try {
      final List<ClientAuthentication> candidates = ClientAuthentication.parseCandidates(httpRequest);
      if (candidates != null && !candidates.isEmpty()) {
        return candidates.getFirst().getClientID().getValue();
      }
      return getParameter(httpRequest.getBodyAsFormParameters(), "client_id");
    }
    catch (final com.nimbusds.oauth2.sdk.ParseException | RuntimeException e) {
      return null;
    }
  }

  /**
   * Assigns the access token lifetime. Defaults to {@link #DEFAULT_ACCESS_TOKEN_LIFETIME}.
   *
   * @param accessTokenLifetime the lifetime
   */
  public void setAccessTokenLifetime(final @NonNull Duration accessTokenLifetime) {
    this.accessTokenLifetime = Objects.requireNonNull(accessTokenLifetime, "accessTokenLifetime must not be null");
  }

  /**
   * Assigns whether access tokens may only be used once. Defaults to {@code true}.
   *
   * @param singleUseAccessTokens whether access tokens may only be used once
   */
  public void setSingleUseAccessTokens(final boolean singleUseAccessTokens) {
    this.singleUseAccessTokens = singleUseAccessTokens;
  }

  /**
   * What the audit knows about the request being processed.
   */
  private static final class AuditState {

    /** The authenticated client, or {@code null} if the client has not been authenticated. */
    private AuditRequester requester;
  }

}
