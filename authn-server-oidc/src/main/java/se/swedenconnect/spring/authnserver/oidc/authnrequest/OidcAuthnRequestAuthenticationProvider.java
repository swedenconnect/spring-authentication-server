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
package se.swedenconnect.spring.authnserver.oidc.authnrequest;

import java.text.ParseException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.factories.DefaultJWSVerifierFactory;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ResponseType;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.auth.ClientAuthenticationMethod;
import com.nimbusds.oauth2.sdk.pkce.CodeChallengeMethod;
import com.nimbusds.oauth2.sdk.util.JSONObjectUtils;
import com.nimbusds.openid.connect.sdk.AuthenticationRequest;
import com.nimbusds.openid.connect.sdk.OIDCClaimsRequest;
import com.nimbusds.openid.connect.sdk.OIDCError;
import com.nimbusds.openid.connect.sdk.Prompt;
import com.nimbusds.openid.connect.sdk.claims.ACR;
import com.nimbusds.openid.connect.sdk.claims.ClaimRequirement;
import com.nimbusds.openid.connect.sdk.claims.ClaimsSetRequest;
import com.nimbusds.openid.connect.sdk.rp.OIDCClientMetadata;

import net.minidev.json.JSONObject;

import se.oidc.nimbus.claims.ParameterConstants;
import se.oidc.nimbus.claims.ScopeConstants;
import se.oidc.nimbus.usermessage.UserMessage;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.error.AuthenticationError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.message.GenericSignMessage;
import se.swedenconnect.spring.authnserver.message.GenericUserMessage;
import se.swedenconnect.spring.authnserver.message.LocalizedMessage;
import se.swedenconnect.spring.authnserver.message.MessageMimeType;
import se.swedenconnect.spring.authnserver.oidc.attributes.requested.OidcRequestedAttributeResolver;
import se.swedenconnect.spring.authnserver.oidc.authentication.OidcAuthenticationRequirements;
import se.swedenconnect.spring.authnserver.oidc.error.OidcErrorMapping;
import se.swedenconnect.spring.authnserver.oidc.error.OidcErrorResponseException;
import se.swedenconnect.spring.authnserver.oidc.error.OidcUnrecoverableError;
import se.swedenconnect.spring.authnserver.oidc.keys.OidcKeys;
import se.swedenconnect.spring.authnserver.oidc.keys.SigningKey;
import se.swedenconnect.spring.authnserver.oidc.scope.BuiltInScopes;
import se.swedenconnect.spring.authnserver.registry.ClientRegistry;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.acceptance.RequesterAcceptance;

/**
 * Validates an OpenID Connect authentication request and turns it into the protocol-neutral authentication
 * requirements.
 * <p>
 * It follows OpenID Connect Core, Section 3.1.2, and the Swedish OpenID Connect Profile, Section 2. In this order: the
 * parameters are parsed, {@code response_type} must be {@code code}, {@code state} must be present unless it is
 * optional, an unsigned request object is rejected when signed request objects are required, the requester acceptance
 * is checked, and PKCE is checked. Then the requirements are built: {@code prompt}, {@code max_age},
 * {@code id_token_hint}, {@code login_hint}, {@code ui_locales}, the requested attributes from the offered scopes and
 * the {@code claims} parameter, the authentication contexts, and the extensions for user messages, authentication
 * providers and signature requests.
 * </p>
 * <p>
 * Every failure is sent to the client as an error response, see {@link OidcErrorResponseException}, except a failure
 * of the client registry during the requester acceptance check, which is unrecoverable.
 * </p>
 * <p>
 * The result is a {@link UserAuthenticationInputToken} holding {@link OidcAuthenticationRequirements} and, as its
 * protocol request data, the {@link OidcAuthnRequestData}.
 * </p>
 *
 * @author Martin Lindström
 */
public class OidcAuthnRequestAuthenticationProvider implements AuthenticationProvider {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(OidcAuthnRequestAuthenticationProvider.class);

  /** The claim name for the authentication context. */
  private static final String ACR_CLAIM = "acr";

  /** The keys of the OpenID Provider, for validating an ID token hint. */
  private final OidcKeys keys;

  /** The issuer of the OpenID Provider. */
  private final String issuer;

  /** The client registry. */
  private final ClientRegistry clientRegistry;

  /** The requester acceptance check. */
  private final RequesterAcceptance requesterAcceptance;

  /** Resolves the requested attributes. */
  private final OidcRequestedAttributeResolver requestedAttributeResolver;

  /** Decodes a signature request passed as a JWT. */
  private final RequestObjectDecoder requestObjectDecoder;

  /** The scopes that the OpenID Provider offers. */
  private final List<String> supportedScopes;

  /** The authentication contexts that the OpenID Provider supports. */
  private final List<String> supportedAuthnContextUris;

  /** Whether user messages are supported. */
  private boolean supportsUserMessage = false;

  /** Whether PKCE is required for all clients, and not only for public clients. */
  private boolean requirePkce = false;

  /** Whether request objects must be signed. */
  private boolean requireSignedRequestObject = false;

  /** Whether {@code state} is required. */
  private boolean requireState = true;

  /**
   * Constructor.
   *
   * @param keys the keys of the OpenID Provider, for validating an ID token hint
   * @param issuer the issuer of the OpenID Provider
   * @param clientRegistry the client registry
   * @param requesterAcceptance the requester acceptance check
   * @param requestedAttributeResolver resolves the requested attributes
   * @param requestObjectDecoder decodes a signature request passed as a JWT
   * @param supportedScopes the scopes that the OpenID Provider offers
   * @param supportedAuthnContextUris the authentication contexts that the OpenID Provider supports
   */
  public OidcAuthnRequestAuthenticationProvider(final @NonNull OidcKeys keys, final @NonNull String issuer,
      final @NonNull ClientRegistry clientRegistry, final @NonNull RequesterAcceptance requesterAcceptance,
      final @NonNull OidcRequestedAttributeResolver requestedAttributeResolver,
      final @NonNull RequestObjectDecoder requestObjectDecoder, final @NonNull List<String> supportedScopes,
      final @NonNull List<String> supportedAuthnContextUris) {
    this.keys = Objects.requireNonNull(keys, "keys must not be null");
    this.issuer = Objects.requireNonNull(issuer, "issuer must not be null");
    this.clientRegistry = Objects.requireNonNull(clientRegistry, "clientRegistry must not be null");
    this.requesterAcceptance = Objects.requireNonNull(requesterAcceptance, "requesterAcceptance must not be null");
    this.requestedAttributeResolver =
        Objects.requireNonNull(requestedAttributeResolver, "requestedAttributeResolver must not be null");
    this.requestObjectDecoder = Objects.requireNonNull(requestObjectDecoder, "requestObjectDecoder must not be null");
    this.supportedScopes = List.copyOf(Objects.requireNonNull(supportedScopes, "supportedScopes must not be null"));
    this.supportedAuthnContextUris = List.copyOf(
        Objects.requireNonNull(supportedAuthnContextUris, "supportedAuthnContextUris must not be null"));
  }

  /**
   * Processes an {@link OidcAuthnRequestAuthenticationToken} into a {@link UserAuthenticationInputToken}.
   *
   * @throws OidcErrorResponseException for errors that are sent to the client
   * @throws UnrecoverableErrorException if the client registry fails during the requester acceptance check
   */
  @Override
  public @NonNull Authentication authenticate(final @NonNull Authentication authentication)
      throws OidcErrorResponseException, UnrecoverableErrorException {

    final OidcAuthnRequestAuthenticationToken token = (OidcAuthnRequestAuthenticationToken) authentication;
    final String logString = token.getLogString();
    final OIDCClientMetadata metadata = token.getClientMetadata();

    final AuthenticationRequest request;
    try {
      request = AuthenticationRequest.parse(token.getParameters());
    }
    catch (final com.nimbusds.oauth2.sdk.ParseException e) {
      final ErrorObject error = e.getErrorObject() != null ? e.getErrorObject() : OAuth2Error.INVALID_REQUEST;
      log.info("Invalid authentication request - {} [{}]", e.getMessage(), logString);
      throw new OidcErrorResponseException(error, e.getMessage(), e);
    }

    if (!ResponseType.CODE.equals(request.getResponseType())) {
      log.info("Unsupported response_type '{}' [{}]", request.getResponseType(), logString);
      throw new OidcErrorResponseException(OAuth2Error.UNSUPPORTED_RESPONSE_TYPE,
          "Only the code response type is supported");
    }
    if (this.requireState && request.getState() == null) {
      throw invalidRequest("Missing state parameter", logString);
    }
    this.checkRequestObjectSigning(token, metadata, logString);

    // Is the client accepted?
    //
    final boolean accepted;
    try {
      accepted = this.requesterAcceptance.isAccepted(token.getRequesterRecord(), this.clientRegistry);
    }
    catch (final ClientRegistryException e) {
      log.error("The client registry failed during the requester acceptance check - {} [{}]", e.getMessage(),
          logString, e);
      throw new UnrecoverableErrorException(OidcUnrecoverableError.CLIENT_LOOKUP_FAILED,
          "The client registry failed during the requester acceptance check", e);
    }
    if (!accepted) {
      log.info("Client is not accepted by the requester acceptance check [{}]", logString);
      throw new OidcErrorResponseException(OidcErrorMapping.of(AuthenticationError.NOT_AUTHORIZED, null),
          AuthenticationError.NOT_AUTHORIZED.getDefaultMessage());
    }

    this.checkPkce(request, metadata, logString);

    final OidcAuthenticationRequirements requirements = this.createAuthenticationRequirements(request, token);
    log.debug("Authentication requirements: {} [{}]", requirements, logString);

    final OidcAuthnRequestData requestData = new OidcAuthnRequestData(token.getResponseTarget(),
        request.getNonce() != null ? request.getNonce().getValue() : null,
        request.getCodeChallenge() != null ? request.getCodeChallenge().getValue() : null,
        request.getCodeChallengeMethod() != null ? request.getCodeChallengeMethod().getValue() : null,
        request.getScope() != null ? request.getScope().toStringList() : List.of(),
        request.getOIDCClaims() != null ? request.getOIDCClaims().toJSONString() : null);

    token.setAuthenticated(true);
    return new UserAuthenticationInputToken(requirements, token.getRequesterRecord().requester(), null, requestData);
  }

  /**
   * Supports {@link OidcAuthnRequestAuthenticationToken}.
   */
  @Override
  public boolean supports(final @NonNull Class<?> authentication) {
    return OidcAuthnRequestAuthenticationToken.class.isAssignableFrom(authentication);
  }

  /**
   * Creates the authentication requirements of the request.
   *
   * @param request the parsed request
   * @param token the request token
   * @return the authentication requirements
   * @throws OidcErrorResponseException for errors that are sent to the client
   */
  protected @NonNull OidcAuthenticationRequirements createAuthenticationRequirements(
      final @NonNull AuthenticationRequest request, final @NonNull OidcAuthnRequestAuthenticationToken token)
      throws OidcErrorResponseException {

    final String logString = token.getLogString();
    final OidcAuthenticationRequirements requirements = new OidcAuthenticationRequirements();

    final Prompt prompt = request.getPrompt();
    if (prompt != null) {
      requirements.setForceAuthn(prompt.contains(Prompt.Type.LOGIN));
      requirements.setPassiveAuthn(prompt.contains(Prompt.Type.NONE));
      requirements.setConsentRequired(prompt.contains(Prompt.Type.CONSENT));
    }
    if (request.getMaxAge() < -1) {
      throw invalidRequest("Invalid max_age parameter", logString);
    }
    if (request.getMaxAge() >= 0) {
      requirements.setMaxAuthnAge(Duration.ofSeconds(request.getMaxAge()));
    }
    if (request.getIDTokenHint() != null) {
      requirements.setIdTokenHintSubject(this.validateIdTokenHint(request.getIDTokenHint(), token.getClientId(),
          logString));
    }
    requirements.setLoginHint(request.getLoginHint());
    if (request.getUILocales() != null) {
      requirements.setUiLocales(request.getUILocales().stream().map(Object::toString).toList());
    }

    // Scopes and claims ...
    //
    final List<String> scopes = new ArrayList<>();
    if (request.getScope() != null) {
      for (final String scope : request.getScope().toStringList()) {
        if (this.supportedScopes.contains(scope)) {
          scopes.add(scope);
        }
        else {
          log.debug("Scope '{}' is not offered - ignored [{}]", scope, logString);
        }
      }
    }
    requirements.setScopes(scopes);
    requirements.setRequestedAttributes(this.requestedAttributeResolver.resolve(
        new Scope(scopes.toArray(String[]::new)), request.getOIDCClaims(), logString));
    requirements.setAuthnContextRequirements(this.resolveAuthnContexts(request, logString));

    // Extensions ...
    //
    requirements.setUserMessage(this.extractUserMessage(token, logString));
    final String authnProvider = getParameter(token, ParameterConstants.REQUESTED_PROVIDER_PARAM_NAME);
    if (authnProvider != null) {
      requirements.setRequestedAuthnProviders(List.of(authnProvider));
    }
    requirements.setSignMessage(this.extractSignMessage(token, scopes, prompt, logString));

    return requirements;
  }

  /**
   * Checks that a request object is signed when that is required, either by the setting or because the client has
   * registered {@code request_object_signing_alg}. A client that has registered an algorithm must use it.
   *
   * @param token the request token
   * @param metadata the client metadata
   * @param logString the log string
   * @throws OidcErrorResponseException with {@code invalid_request_object}
   */
  private void checkRequestObjectSigning(final @NonNull OidcAuthnRequestAuthenticationToken token,
      final @NonNull OIDCClientMetadata metadata, final @NonNull String logString) throws OidcErrorResponseException {

    final RequestObjectDecoder.DecodedJwt requestObject = token.getRequestObject();
    if (requestObject == null) {
      return;
    }
    final JWSAlgorithm registered = metadata.getRequestObjectJWSAlg();
    final JWSAlgorithm used = requestObject.signingAlgorithm();
    if (registered != null && !"none".equals(registered.getName())) {
      if (!registered.equals(used)) {
        log.info("Request object must be signed with {}, the client's request_object_signing_alg, but was {} [{}]",
            registered, used != null ? used : "not signed", logString);
        throw new OidcErrorResponseException(OAuth2Error.INVALID_REQUEST_OBJECT,
            "The request object must be signed with " + registered.getName());
      }
    }
    else if (this.requireSignedRequestObject && used == null) {
      log.info("Unsigned request object rejected - signed request objects are required [{}]", logString);
      throw new OidcErrorResponseException(OAuth2Error.INVALID_REQUEST_OBJECT, "The request object must be signed");
    }
  }

  /**
   * Checks the PKCE parameters. The {@code plain} method is always rejected, and a challenge is required from a public
   * client, and from every client when PKCE is required.
   *
   * @param request the request
   * @param metadata the client metadata
   * @param logString the log string
   * @throws OidcErrorResponseException with {@code invalid_request}
   */
  private void checkPkce(final @NonNull AuthenticationRequest request, final @NonNull OIDCClientMetadata metadata,
      final @NonNull String logString) throws OidcErrorResponseException {

    if (request.getCodeChallenge() == null) {
      if (request.getCodeChallengeMethod() != null) {
        throw invalidRequest("code_challenge_method given without code_challenge", logString);
      }
      final boolean publicClient = ClientAuthenticationMethod.NONE.equals(metadata.getTokenEndpointAuthMethod());
      if (this.requirePkce || publicClient) {
        throw invalidRequest(publicClient
            ? "PKCE is required for public clients - missing code_challenge"
            : "PKCE is required - missing code_challenge", logString);
      }
      return;
    }
    if (!CodeChallengeMethod.S256.equals(request.getCodeChallengeMethod())) {
      throw invalidRequest("Only the S256 code_challenge_method is supported", logString);
    }
  }

  /**
   * Validates an ID token hint: it must be signed by one of the signing keys of the OpenID Provider, be issued by it,
   * and be issued to the client. An expired token is accepted.
   *
   * @param idTokenHint the ID token hint
   * @param clientId the {@code client_id}
   * @param logString the log string
   * @return the subject of the ID token
   * @throws OidcErrorResponseException with {@code invalid_request} if the hint is invalid
   */
  private @NonNull String validateIdTokenHint(final @NonNull JWT idTokenHint, final @NonNull String clientId,
      final @NonNull String logString) throws OidcErrorResponseException {

    if (!(idTokenHint instanceof final SignedJWT signed)) {
      throw invalidRequest("The id_token_hint is not a signed JWT", logString);
    }
    final String keyId = signed.getHeader().getKeyID();
    final DefaultJWSVerifierFactory factory = new DefaultJWSVerifierFactory();
    boolean verified = false;
    for (final SigningKey key : this.keys.getSigningKeys()) {
      if (keyId != null && !keyId.equals(key.getKeyId())
          || !key.supports(signed.getHeader().getAlgorithm())) {
        continue;
      }
      try {
        if (signed.verify(factory.createJWSVerifier(signed.getHeader(), key.getCredential().getPublicKey()))) {
          verified = true;
          break;
        }
      }
      catch (final JOSEException | IllegalStateException e) {
        log.debug("Failed to verify id_token_hint with key '{}' - {} [{}]", key.getKeyId(), e.getMessage(),
            logString);
      }
    }
    if (!verified) {
      throw invalidRequest("The id_token_hint was not signed by this OpenID Provider", logString);
    }
    final JWTClaimsSet claims;
    try {
      claims = signed.getJWTClaimsSet();
    }
    catch (final ParseException e) {
      throw invalidRequest("The claims of the id_token_hint could not be parsed", logString);
    }
    if (!this.issuer.equals(claims.getIssuer())) {
      throw invalidRequest("The id_token_hint was not issued by this OpenID Provider", logString);
    }
    if (claims.getAudience() == null || !claims.getAudience().contains(clientId)) {
      throw invalidRequest("The id_token_hint was not issued to the client", logString);
    }
    if (!StringUtils.hasText(claims.getSubject())) {
      throw invalidRequest("The id_token_hint has no subject", logString);
    }
    return claims.getSubject();
  }

  /**
   * Works out the authentication contexts. Values of {@code acr} in the {@code claims} parameter win over
   * {@code acr_values}. Values that the OpenID Provider does not support are left out. If essential values are
   * requested and none of them is supported, the request fails with {@code unmet_authentication_requirements}.
   *
   * @param request the request
   * @param logString the log string
   * @return the authentication context URIs, in the requester's order of preference
   * @throws OidcErrorResponseException for unmet essential values
   */
  private @NonNull List<String> resolveAuthnContexts(final @NonNull AuthenticationRequest request,
      final @NonNull String logString) throws OidcErrorResponseException {

    List<String> requested = List.of();
    boolean essential = false;
    final ClaimsSetRequest.Entry acrEntry = getAcrEntry(request.getOIDCClaims());
    if (acrEntry != null && (acrEntry.getValue() != null || acrEntry.getValues() != null)) {
      requested = acrEntry.getValues() != null ? acrEntry.getValues() : List.of(acrEntry.getValue());
      essential = acrEntry.getClaimRequirement() == ClaimRequirement.ESSENTIAL;
    }
    else if (request.getACRValues() != null) {
      requested = request.getACRValues().stream().map(ACR::getValue).toList();
    }
    final List<String> supported = requested.stream().filter(this.supportedAuthnContextUris::contains).toList();
    if (essential && supported.isEmpty()) {
      log.info("None of the essential acr values {} is supported [{}]", requested, logString);
      throw new OidcErrorResponseException(OIDCError.UNMET_AUTHENTICATION_REQUIREMENTS,
          "None of the essential acr values is supported");
    }
    if (supported.size() < requested.size()) {
      log.debug("Unsupported acr values left out - requested: {}, supported: {} [{}]", requested, supported,
          logString);
    }
    return supported;
  }

  /**
   * Gets the {@code acr} entry of the claims parameter, from the ID token or the UserInfo section.
   *
   * @param claims the claims parameter, may be {@code null}
   * @return the entry, or {@code null}
   */
  private static ClaimsSetRequest.@Nullable Entry getAcrEntry(final @Nullable OIDCClaimsRequest claims) {
    if (claims == null) {
      return null;
    }
    if (claims.getIDTokenClaimsRequest() != null && claims.getIDTokenClaimsRequest().get(ACR_CLAIM) != null) {
      return claims.getIDTokenClaimsRequest().get(ACR_CLAIM);
    }
    return claims.getUserInfoClaimsRequest() != null ? claims.getUserInfoClaimsRequest().get(ACR_CLAIM) : null;
  }

  /**
   * Extracts the user message of [OIDC.Sweden.RPar]. It is ignored if user messages are not supported.
   *
   * @param token the request token
   * @param logString the log string
   * @return the user message, or {@code null}
   * @throws OidcErrorResponseException for an invalid user message, when user messages are supported
   */
  private @Nullable GenericUserMessage extractUserMessage(final @NonNull OidcAuthnRequestAuthenticationToken token,
      final @NonNull String logString) throws OidcErrorResponseException {

    final String value = getParameter(token, ParameterConstants.USER_MESSAGE_PARAM_NAME);
    if (value == null) {
      return null;
    }
    if (!this.supportsUserMessage) {
      log.debug("User message received, but user messages are not supported - ignored [{}]", logString);
      return null;
    }
    try {
      final UserMessage userMessage = UserMessage.parse(JSONObjectUtils.parse(value));
      final GenericUserMessage result =
          new GenericUserMessage(toLocalizedMessages(userMessage), toMimeType(userMessage.getMimeType()));
      log.debug("User message present for languages {} [{}]",
          result.getMessages().stream().map(LocalizedMessage::language).toList(), logString);
      return result;
    }
    catch (final com.nimbusds.oauth2.sdk.ParseException | IllegalArgumentException e) {
      throw invalidRequest("Invalid user message - " + e.getMessage(), logString);
    }
  }

  /**
   * Extracts the sign message of a signature request, following the Signature Extension for OpenID Connect. A
   * signature request is only processed when the sign scope or the sign approval scope is requested and offered. The
   * signature request parameter must then be present and signed, either as a JWT of its own or in a signed request
   * object, and {@code prompt} must hold {@code login} and {@code consent}. The data to be signed must be present for
   * the sign scope, and must not be present for sign approval only.
   *
   * @param token the request token
   * @param scopes the honoured scopes
   * @param prompt the prompt, may be {@code null}
   * @param logString the log string
   * @return the sign message, or {@code null} if no signature is requested
   * @throws OidcErrorResponseException with {@code invalid_request} for an invalid signature request
   */
  private @Nullable GenericSignMessage extractSignMessage(final @NonNull OidcAuthnRequestAuthenticationToken token,
      final @NonNull List<String> scopes, final @Nullable Prompt prompt, final @NonNull String logString)
      throws OidcErrorResponseException {

    final boolean sign = scopes.contains(ScopeConstants.SIGN.getValue());
    final boolean signApproval = scopes.contains(BuiltInScopes.SIGN_APPROVAL.getValue());
    if (!sign && !signApproval) {
      if (getParameter(token, ParameterConstants.SIGN_REQUEST_PARAM_NAME) != null) {
        log.debug("Signature request received without a sign scope - ignored [{}]", logString);
      }
      return null;
    }
    if (prompt == null || !prompt.contains(Prompt.Type.LOGIN) || !prompt.contains(Prompt.Type.CONSENT)) {
      throw invalidRequest("A signature request requires prompt to hold login and consent", logString);
    }

    final Map<String, Object> signRequest;
    final RequestObjectDecoder.DecodedJwt requestObject = token.getRequestObject();
    final Object inRequestObject = requestObject != null
        ? requestObject.claims().getClaim(ParameterConstants.SIGN_REQUEST_PARAM_NAME)
        : null;
    if (inRequestObject != null) {
      if (requestObject.signingAlgorithm() == null) {
        throw invalidRequest("A signature request in a request object requires the request object to be signed",
            logString);
      }
      if (!(inRequestObject instanceof final Map<?, ?> map)) {
        throw invalidRequest("The signature request of the request object is not a JSON object", logString);
      }
      signRequest = toStringKeyMap(map);
    }
    else {
      final String jwt = getParameter(token, ParameterConstants.SIGN_REQUEST_PARAM_NAME);
      if (jwt == null) {
        throw invalidRequest("Missing signature request parameter", logString);
      }
      signRequest = this.requestObjectDecoder.decodeSignedParameter(jwt, token.getClientId(),
          token.getClientMetadata(), "signature request", logString).claims().toJSONObject();
    }

    final Object tbsData = signRequest.get("tbs_data");
    if (sign && !(tbsData instanceof String)) {
      throw invalidRequest("The signature request has no tbs_data", logString);
    }
    if (!sign && tbsData != null) {
      throw invalidRequest("The signature request must not hold tbs_data for signature approval", logString);
    }
    if (!(signRequest.get("sign_message") instanceof final Map<?, ?> signMessage)) {
      throw invalidRequest("The signature request has no sign_message", logString);
    }
    try {
      final UserMessage message = UserMessage.parse(new JSONObject(toStringKeyMap(signMessage)));
      final GenericSignMessage result = new GenericSignMessage(toLocalizedMessages(message),
          toMimeType(message.getMimeType()), true, (String) tbsData);
      log.debug("Signature request present - {} [{}]", sign ? "sign" : "sign approval", logString);
      return result;
    }
    catch (final com.nimbusds.oauth2.sdk.ParseException | IllegalArgumentException e) {
      throw invalidRequest("Invalid signature request - " + e.getMessage(), logString);
    }
  }

  /**
   * Turns the messages of a {@link UserMessage} into localized messages.
   *
   * @param message the message
   * @return the localized messages
   */
  private static @NonNull List<LocalizedMessage> toLocalizedMessages(final @NonNull UserMessage message) {
    return message.getMessages().stream()
        .map(m -> new LocalizedMessage(m.getLanguage() != null ? m.getLanguage().toString() : null, m.getMessage()))
        .toList();
  }

  /**
   * Parses a message MIME type. OpenID Connect allows {@code text/plain} and {@code text/markdown}.
   *
   * @param mimeType the MIME type, may be {@code null}
   * @return the MIME type
   * @throws IllegalArgumentException for a MIME type that is not allowed
   */
  private static @NonNull MessageMimeType toMimeType(final @Nullable String mimeType) {
    final MessageMimeType type = MessageMimeType.parse(mimeType);
    if (type == MessageMimeType.TEXT_HTML || MessageMimeType.SAML_TEXT.equalsIgnoreCase(Objects.toString(mimeType))) {
      throw new IllegalArgumentException("Unsupported message MIME type: " + mimeType);
    }
    return type;
  }

  /**
   * Gets a parameter of the request.
   *
   * @param token the request token
   * @param name the parameter name
   * @return the value, or {@code null}
   */
  private static @Nullable String getParameter(final @NonNull OidcAuthnRequestAuthenticationToken token,
      final @NonNull String name) {
    final List<String> values = token.getParameters().get(name);
    return values != null && !values.isEmpty() && StringUtils.hasText(values.getFirst()) ? values.getFirst() : null;
  }

  /**
   * Copies a map, turning its keys into strings.
   *
   * @param map the map
   * @return a map with string keys
   */
  private static @NonNull Map<String, Object> toStringKeyMap(final @NonNull Map<?, ?> map) {
    final JSONObject result = new JSONObject();
    map.forEach((k, v) -> result.put(String.valueOf(k), v));
    return result;
  }

  /**
   * Creates the exception for an invalid request, and logs it.
   *
   * @param description the description
   * @param logString the log string
   * @return an {@link OidcErrorResponseException}
   */
  private static @NonNull OidcErrorResponseException invalidRequest(final @NonNull String description,
      final @NonNull String logString) {
    log.info("Invalid authentication request - {} [{}]", description, logString);
    return new OidcErrorResponseException(OAuth2Error.INVALID_REQUEST, description);
  }

  /**
   * Assigns whether user messages are supported. Defaults to {@code false}.
   *
   * @param supportsUserMessage whether user messages are supported
   */
  public void setSupportsUserMessage(final boolean supportsUserMessage) {
    this.supportsUserMessage = supportsUserMessage;
  }

  /**
   * Assigns whether PKCE is required for all clients. Defaults to {@code false}, meaning that PKCE is required for
   * public clients only.
   *
   * @param requirePkce whether PKCE is required for all clients
   */
  public void setRequirePkce(final boolean requirePkce) {
    this.requirePkce = requirePkce;
  }

  /**
   * Assigns whether request objects must be signed. Defaults to {@code false}. A client that has registered
   * {@code request_object_signing_alg} must always sign with that algorithm.
   *
   * @param requireSignedRequestObject whether request objects must be signed
   */
  public void setRequireSignedRequestObject(final boolean requireSignedRequestObject) {
    this.requireSignedRequestObject = requireSignedRequestObject;
  }

  /**
   * Assigns whether {@code state} is required. Defaults to {@code true}.
   *
   * @param requireState whether {@code state} is required
   */
  public void setRequireState(final boolean requireState) {
    this.requireState = requireState;
  }

}
