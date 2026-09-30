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
package se.swedenconnect.spring.authnserver.oidc.response;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.Serializable;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.release.AttributeReleaseManager;
import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.error.AuthenticationError;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.oidc.attributes.DeliveredClaims;
import se.swedenconnect.spring.authnserver.oidc.attributes.OidcAttributeMapping;
import se.swedenconnect.spring.authnserver.oidc.authentication.OidcAuthenticationRequirements;
import se.swedenconnect.spring.authnserver.oidc.authnrequest.OidcAuthnRequestData;
import se.swedenconnect.spring.authnserver.oidc.error.OidcUnrecoverableError;
import se.swedenconnect.spring.authnserver.oidc.subject.SubjectGeneratorFactory;
import se.swedenconnect.spring.authnserver.oidc.token.AuthorizationCodeData;
import se.swedenconnect.spring.authnserver.oidc.token.AuthorizationCodeStore;
import se.swedenconnect.spring.authnserver.registry.ClientRegistry;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;
import se.swedenconnect.spring.authnserver.web.UserAuthenticationFlow;

/**
 * Answers the client once the user has been authenticated: issues the authorization code and sends it to the redirect
 * URI, in the response mode of the request and with {@code state}.
 * <p>
 * Before the code is issued, the {@code sub} of the user for the client is worked out, and checked against a
 * {@code sub} that the client asked for with a value in the {@code claims} parameter or implied by
 * {@code id_token_hint}. A mismatch is answered with {@code access_denied} and no code. The attributes are then
 * released, with the OpenID Connect producers and voters followed by the shared ones, and turned into the claims for
 * the ID token and for the UserInfo endpoint, see {@link DeliveredClaims}. The code is bound to all of this.
 * </p>
 * <p>
 * The authentication is kept in the session for single sign-on once the code has been issued. An error raised on the
 * way, such as when the attributes are released, removes the authentication from the session, as any failed
 * authentication does.
 * </p>
 *
 * @author Martin Lindström
 */
public class OidcUserAuthenticationResponder {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(OidcUserAuthenticationResponder.class);

  /** The default authorization code lifetime, 1 minute. */
  public static final Duration DEFAULT_CODE_LIFETIME = Duration.ofMinutes(1);

  /** The client registry. */
  private final ClientRegistry clientRegistry;

  /** Creates the subject generators. */
  private final SubjectGeneratorFactory subjectGeneratorFactory;

  /** Releases the attributes. */
  private final AttributeReleaseManager attributeReleaseManager;

  /** Maps attributes to claims. */
  private final OidcAttributeMapping attributeMapping;

  /** Keeps the authorization codes. */
  private final AuthorizationCodeStore codeStore;

  /** Sends the response. */
  private final OidcResponseSender responseSender;

  /** Keeps the authentication in the session. */
  private final UserAuthenticationFlow flow;

  /** The authorization code lifetime. */
  private Duration codeLifetime = DEFAULT_CODE_LIFETIME;

  /** How long a used code is kept, on top of its lifetime, so that a second use can be detected. */
  private Duration codeRetention = Duration.ofMinutes(5);

  /**
   * Constructor.
   *
   * @param clientRegistry the client registry
   * @param subjectGeneratorFactory creates the subject generators
   * @param attributeReleaseManager releases the attributes
   * @param attributeMapping maps attributes to claims
   * @param codeStore keeps the authorization codes
   * @param responseSender sends the response
   * @param flow keeps the authentication in the session
   */
  public OidcUserAuthenticationResponder(final @NonNull ClientRegistry clientRegistry,
      final @NonNull SubjectGeneratorFactory subjectGeneratorFactory,
      final @NonNull AttributeReleaseManager attributeReleaseManager,
      final @NonNull OidcAttributeMapping attributeMapping, final @NonNull AuthorizationCodeStore codeStore,
      final @NonNull OidcResponseSender responseSender, final @NonNull UserAuthenticationFlow flow) {
    this.clientRegistry = Objects.requireNonNull(clientRegistry, "clientRegistry must not be null");
    this.subjectGeneratorFactory =
        Objects.requireNonNull(subjectGeneratorFactory, "subjectGeneratorFactory must not be null");
    this.attributeReleaseManager =
        Objects.requireNonNull(attributeReleaseManager, "attributeReleaseManager must not be null");
    this.attributeMapping = Objects.requireNonNull(attributeMapping, "attributeMapping must not be null");
    this.codeStore = Objects.requireNonNull(codeStore, "codeStore must not be null");
    this.responseSender = Objects.requireNonNull(responseSender, "responseSender must not be null");
    this.flow = Objects.requireNonNull(flow, "flow must not be null");
  }

  /**
   * Issues the authorization code, keeps the authentication for single sign-on, and sends the code to the client.
   *
   * @param request the HTTP servlet request
   * @param response the HTTP servlet response
   * @param token the request being answered
   * @param authentication the authentication
   * @throws AuthenticationErrorException if the user is not the requested subject, or the attribute release fails,
   *     in which case the session authentication has been removed
   * @throws UnrecoverableErrorException if the client cannot be looked up or its {@code sub} cannot be worked out
   * @throws IOException if the response cannot be sent
   */
  public void sendResponse(final @NonNull HttpServletRequest request, final @NonNull HttpServletResponse response,
      final @NonNull UserAuthenticationInputToken token, final @NonNull UserAuthentication authentication)
      throws AuthenticationErrorException, UnrecoverableErrorException, IOException {

    final OidcAuthnRequestData data = getRequestData(token);
    final OidcResponseTarget target = data.responseTarget();
    final AuthenticationRequirements requirements = token.getAuthnRequirements();
    final AuthenticatedUser user = authentication.getAuthenticatedUser();
    final String logString = token.getLogString();

    final OIDCClientMetadata metadata = this.getClientMetadata(target.clientId(), logString);
    final String subject = this.subjectGeneratorFactory.getSubjectGenerator(metadata.getSubjectType(),
            metadata.getSectorIDURI(), metadata.getRedirectionURIs())
        .getSubject(user, token.getRequester())
        .getValue();

    final List<GenericAttribute<? extends Serializable>> released;
    try {
      this.checkRequestedSubject(subject, requirements, data, logString);
      released = this.attributeReleaseManager.releaseAttributes(authentication);
    }
    catch (final AuthenticationErrorException e) {
      this.flow.failAuthentication(request, response, e);
      throw e;
    }
    final DeliveredClaims claims =
        DeliveredClaims.of(released, requirements.getRequestedAttributes(), this.attributeMapping);

    if (requirements.isVoluntaryAuthnContexts() && !data.requestedAcrValues().isEmpty()
        && !data.requestedAcrValues().contains(user.getAuthnContextUri())) {
      log.info("None of the requested acr values {} could be met - the ID token holds acr '{}' [{}]",
          data.requestedAcrValues(), user.getAuthnContextUri(), logString);
    }

    final Instant now = Instant.now();
    final Instant expiresAt = now.plus(this.codeLifetime);
    final String code = new AuthorizationCode().getValue();
    this.codeStore.save(new AuthorizationCodeData(code, target.clientId(), target.redirectUri(),
        data.codeChallenge(), data.codeChallengeMethod(), data.nonce(),
        requirements instanceof final OidcAuthenticationRequirements oidc ? oidc.getScopes() : data.scopes(),
        subject, user, requirements, claims.idToken().toJSONString(), claims.userInfo().toJSONString(), now,
        expiresAt, expiresAt.plus(this.codeRetention)));

    this.flow.saveAuthentication(authentication, request, response);

    log.debug("Sending authorization code to '{}' for '{}' [{}]", target.redirectUri(), authentication.getName(),
        logString);
    this.responseSender.send(request, response, target, Map.of("code", code));
  }

  /**
   * Gets the OpenID Connect data of the request being answered.
   *
   * @param token the request
   * @return the request data
   * @throws UnrecoverableErrorException if the request carries no OpenID Connect data
   */
  public static @NonNull OidcAuthnRequestData getRequestData(final @NonNull UserAuthenticationInputToken token)
      throws UnrecoverableErrorException {
    if (token.getProtocolRequestData() instanceof final OidcAuthnRequestData data) {
      return data;
    }
    throw new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL,
        "No OpenID Connect request data available for " + token.getLogString());
  }

  /**
   * Assigns the authorization code lifetime. Defaults to {@link #DEFAULT_CODE_LIFETIME}.
   *
   * @param codeLifetime the lifetime
   */
  public void setCodeLifetime(final @NonNull Duration codeLifetime) {
    this.codeLifetime = Objects.requireNonNull(codeLifetime, "codeLifetime must not be null");
  }

  /**
   * Assigns how long a used code is kept after it has expired, so that a second use can be detected and the access
   * token issued for it revoked. It should be at least the access token lifetime. Defaults to 5 minutes.
   *
   * @param codeRetention the retention
   */
  public void setCodeRetention(final @NonNull Duration codeRetention) {
    this.codeRetention = Objects.requireNonNull(codeRetention, "codeRetention must not be null");
  }

  /**
   * Looks up the metadata of the client.
   *
   * @param clientId the {@code client_id}
   * @param logString the log string
   * @return the client metadata
   * @throws UnrecoverableErrorException if the client cannot be looked up
   */
  private @NonNull OIDCClientMetadata getClientMetadata(final @NonNull String clientId,
      final @NonNull String logString) throws UnrecoverableErrorException {
    final RequesterRecord record;
    try {
      record = this.clientRegistry.lookup(AuthenticationProtocol.OIDC, clientId);
    }
    catch (final ClientRegistryException e) {
      log.error("Failed to look up client in the client registry - {} [{}]", e.getMessage(), logString, e);
      throw new UnrecoverableErrorException(OidcUnrecoverableError.CLIENT_LOOKUP_FAILED,
          "Failed to look up client in the client registry", e);
    }
    if (record == null || !(record.protocolMetadata() instanceof final OIDCClientMetadata metadata)) {
      log.info("Client is no longer known [{}]", logString);
      throw new UnrecoverableErrorException(OidcUnrecoverableError.UNKNOWN_CLIENT,
          "Client %s is not known".formatted(clientId));
    }
    return metadata;
  }

  /**
   * Checks the {@code sub} against a {@code sub} that the client asked for, with a value in the {@code claims}
   * parameter or implied by {@code id_token_hint}.
   *
   * @param subject the {@code sub} of the authenticated user
   * @param requirements the requirements
   * @param data the request data
   * @param logString the log string
   * @throws AuthenticationErrorException with {@link AuthenticationError#UNKNOWN_PRINCIPAL} for a mismatch
   */
  private void checkRequestedSubject(final @NonNull String subject,
      final @NonNull AuthenticationRequirements requirements, final @NonNull OidcAuthnRequestData data,
      final @NonNull String logString) throws AuthenticationErrorException {

    final List<List<String>> requested = new ArrayList<>(getRequestedSubjects(data.claimsRequest()));
    if (requirements instanceof final OidcAuthenticationRequirements oidc && oidc.getIdTokenHintSubject() != null) {
      requested.add(List.of(oidc.getIdTokenHintSubject()));
    }
    if (requested.stream().anyMatch(values -> !values.contains(subject))) {
      log.info("The authenticated user is not the subject that the client asked for [{}]", logString);
      throw new AuthenticationErrorException(AuthenticationError.UNKNOWN_PRINCIPAL,
          "The authenticated user is not the requested subject");
    }
  }

  /**
   * Gets the {@code sub} values asked for in the {@code claims} parameter, per section of the parameter. The user must
   * be one of the values of each section.
   *
   * @param claimsRequest the {@code claims} parameter as JSON, or {@code null}
   * @return the requested values, possibly empty
   */
  private static @NonNull List<List<String>> getRequestedSubjects(final @Nullable String claimsRequest) {
    if (claimsRequest == null) {
      return List.of();
    }
    final OIDCClaimsRequest claims;
    try {
      claims = OIDCClaimsRequest.parse(claimsRequest);
    }
    catch (final ParseException e) {
      return List.of();
    }
    final List<List<String>> subjects = new ArrayList<>();
    for (final ClaimsSetRequest section : List.of(
        Objects.requireNonNullElseGet(claims.getIDTokenClaimsRequest(), ClaimsSetRequest::new),
        Objects.requireNonNullElseGet(claims.getUserInfoClaimsRequest(), ClaimsSetRequest::new))) {
      final ClaimsSetRequest.Entry entry = section.get("sub");
      if (entry == null) {
        continue;
      }
      if (entry.getValue() != null) {
        subjects.add(List.of(entry.getValue()));
      }
      else if (entry.getValues() != null && !entry.getValues().isEmpty()) {
        subjects.add(entry.getValues());
      }
    }
    return subjects;
  }

}
