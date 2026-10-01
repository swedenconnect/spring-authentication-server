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
package se.swedenconnect.spring.authnserver.saml.authnrequest;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.jspecify.annotations.NonNull;
import org.jspecify.annotations.Nullable;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.IDPEntry;
import org.opensaml.saml.saml2.core.RequesterID;
import org.opensaml.saml.saml2.core.Scoping;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.util.StringUtils;

import se.swedenconnect.opensaml.common.utils.SerializableOpenSamlObject;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.opensaml.sweid.saml2.authn.umsg.Message;
import se.swedenconnect.opensaml.sweid.saml2.authn.umsg.UserMessage;
import se.swedenconnect.opensaml.sweid.saml2.signservice.sap.SADRequest;
import se.swedenconnect.opensaml.sweid.saml2.signservice.sap.SADVersion;
import se.swedenconnect.spring.authnserver.audit.AuditFlowData;
import se.swedenconnect.spring.authnserver.audit.AuditRequestContext;
import se.swedenconnect.spring.authnserver.audit.AuditRequester;
import se.swedenconnect.spring.authnserver.authentication.OriginalRequester;
import se.swedenconnect.spring.authnserver.authentication.provider.UserAuthenticationInputToken;
import se.swedenconnect.spring.authnserver.error.AuthenticationError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.message.GenericUserMessage;
import se.swedenconnect.spring.authnserver.message.LocalizedMessage;
import se.swedenconnect.spring.authnserver.message.MessageMimeType;
import se.swedenconnect.spring.authnserver.registry.ClientRegistry;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;
import se.swedenconnect.spring.authnserver.registry.acceptance.RequesterAcceptance;
import se.swedenconnect.spring.authnserver.saml.attributes.requested.RequestedAttributeContext;
import se.swedenconnect.spring.authnserver.saml.audit.Saml2AuditData;
import se.swedenconnect.spring.authnserver.saml.attributes.requested.SamlRequestedAttributeResolver;
import se.swedenconnect.spring.authnserver.saml.authentication.SadRequestExtension;
import se.swedenconnect.spring.authnserver.saml.authentication.SamlAuthenticationRequirements;
import se.swedenconnect.spring.authnserver.saml.authnrequest.validation.AuthnRequestValidator;
import se.swedenconnect.spring.authnserver.saml.error.SamlErrorStatus;
import se.swedenconnect.spring.authnserver.saml.error.SamlErrorStatusException;
import se.swedenconnect.spring.authnserver.saml.error.SamlUnrecoverableError;
import se.swedenconnect.spring.authnserver.saml.nameid.NameIDGenerator;
import se.swedenconnect.spring.authnserver.saml.nameid.NameIDGeneratorFactory;
import se.swedenconnect.spring.authnserver.saml.response.Saml2ResponseAttributes;

/**
 * Validates a decoded authentication request and turns it into the protocol-neutral authentication requirements.
 * <p>
 * In this order: the replay check, the assertion consumer service, the signature, the check that assertions can be
 * encrypted, the client certificate of a Holder-of-key request, the requester acceptance, the {@code NameIDPolicy},
 * and finally the authentication requirements with the requested attributes, the requested authentication contexts
 * and the extensions.
 * </p>
 * <p>
 * Failures before the assertion consumer service has been established are unrecoverable. Once it has been
 * established, the {@link Saml2ResponseAttributes} are kept on the HTTP request, and a failure is reported to the
 * Service Provider with a {@link SamlErrorStatusException}.
 * </p>
 * <p>
 * The result is a {@link UserAuthenticationInputToken} holding {@link SamlAuthenticationRequirements} and, as its
 * protocol request data, the {@link Saml2AuthnRequestData}. The Service Provider counts as verified for the audit once
 * the signature has been checked.
 * </p>
 *
 * @author Martin Lindström
 */
public class Saml2AuthnRequestAuthenticationProvider implements AuthenticationProvider {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(Saml2AuthnRequestAuthenticationProvider.class);

  /** The replay validator. */
  private final AuthnRequestValidator replayValidator;

  /** The assertion consumer service validator. */
  private final AuthnRequestValidator assertionConsumerServiceValidator;

  /** The signature validator. */
  private final AuthnRequestValidator signatureValidator;

  /** The validator checking that assertions can be encrypted. */
  private final AuthnRequestValidator encryptCapabilitiesValidator;

  /** The client registry. */
  private final ClientRegistry clientRegistry;

  /** The requester acceptance check. */
  private final RequesterAcceptance requesterAcceptance;

  /** The factory for NameID generators. */
  private final NameIDGeneratorFactory nameIdGeneratorFactory;

  /** Resolves the requested attributes. */
  private final SamlRequestedAttributeResolver requestedAttributeResolver;

  /** Resolves the requested authentication context. */
  private final AuthnContextResolver authnContextResolver;

  /** Extracts the sign message, or {@code null}. */
  private final SignMessageExtractor signMessageExtractor;

  /** Whether user messages are supported. */
  private final boolean supportsUserMessage;

  /**
   * Constructor.
   *
   * @param replayValidator the replay validator
   * @param assertionConsumerServiceValidator the assertion consumer service validator
   * @param signatureValidator the signature validator
   * @param encryptCapabilitiesValidator the validator checking that assertions can be encrypted
   * @param clientRegistry the client registry
   * @param requesterAcceptance the requester acceptance check
   * @param nameIdGeneratorFactory the factory for NameID generators
   * @param requestedAttributeResolver resolves the requested attributes
   * @param authnContextResolver resolves the requested authentication context
   * @param signMessageExtractor extracts the sign message, or {@code null} if sign messages are not supported
   * @param supportsUserMessage whether user messages are supported
   */
  public Saml2AuthnRequestAuthenticationProvider(
      final @NonNull AuthnRequestValidator replayValidator,
      final @NonNull AuthnRequestValidator assertionConsumerServiceValidator,
      final @NonNull AuthnRequestValidator signatureValidator,
      final @NonNull AuthnRequestValidator encryptCapabilitiesValidator,
      final @NonNull ClientRegistry clientRegistry,
      final @NonNull RequesterAcceptance requesterAcceptance,
      final @NonNull NameIDGeneratorFactory nameIdGeneratorFactory,
      final @NonNull SamlRequestedAttributeResolver requestedAttributeResolver,
      final @NonNull AuthnContextResolver authnContextResolver,
      final @Nullable SignMessageExtractor signMessageExtractor,
      final boolean supportsUserMessage) {
    this.replayValidator = Objects.requireNonNull(replayValidator, "replayValidator must not be null");
    this.assertionConsumerServiceValidator = Objects.requireNonNull(assertionConsumerServiceValidator,
        "assertionConsumerServiceValidator must not be null");
    this.signatureValidator = Objects.requireNonNull(signatureValidator, "signatureValidator must not be null");
    this.encryptCapabilitiesValidator =
        Objects.requireNonNull(encryptCapabilitiesValidator, "encryptCapabilitiesValidator must not be null");
    this.clientRegistry = Objects.requireNonNull(clientRegistry, "clientRegistry must not be null");
    this.requesterAcceptance = Objects.requireNonNull(requesterAcceptance, "requesterAcceptance must not be null");
    this.nameIdGeneratorFactory =
        Objects.requireNonNull(nameIdGeneratorFactory, "nameIdGeneratorFactory must not be null");
    this.requestedAttributeResolver =
        Objects.requireNonNull(requestedAttributeResolver, "requestedAttributeResolver must not be null");
    this.authnContextResolver = Objects.requireNonNull(authnContextResolver, "authnContextResolver must not be null");
    this.signMessageExtractor = signMessageExtractor;
    this.supportsUserMessage = supportsUserMessage;
  }

  /**
   * Processes a {@link Saml2AuthnRequestAuthenticationToken} into a {@link UserAuthenticationInputToken}.
   *
   * @throws UnrecoverableErrorException for errors that cannot be reported to the Service Provider
   * @throws SamlErrorStatusException for errors that are reported to the Service Provider
   */
  @Override
  public @NonNull Authentication authenticate(final @NonNull Authentication authentication)
      throws UnrecoverableErrorException, SamlErrorStatusException {

    final Saml2AuthnRequestAuthenticationToken token = (Saml2AuthnRequestAuthenticationToken) authentication;
    final EntityDescriptor peerMetadata = Objects.requireNonNull(token.getPeerMetadata(), "No peer metadata");
    final RequesterRecord record = Objects.requireNonNull(token.getRequesterRecord(), "No requester record");

    this.replayValidator.validate(token);
    this.assertionConsumerServiceValidator.validate(token);

    // From now on a failure is reported to the Service Provider ...
    //
    final Saml2ResponseAttributes responseAttributes = new Saml2ResponseAttributes(
        Objects.requireNonNull(token.getAssertionConsumerServiceUrl()), token.getAuthnRequest().getID(),
        token.getRelayState(), peerMetadata);
    if (token.getHttpServletRequest() != null) {
      Saml2ResponseAttributes.setOnRequest(token.getHttpServletRequest(), responseAttributes);
    }

    this.signatureValidator.validate(token);
    if (token.getHttpServletRequest() != null) {
      AuditRequestContext.get(token.getHttpServletRequest()).setRequester(AuditRequester.of(record, true));
    }
    this.encryptCapabilitiesValidator.validate(token);

    // A Holder-of-key assertion is bound to the certificate of the TLS handshake ...
    //
    if (token.isHolderOfKey() && token.getClientCertificate() == null) {
      log.info("No client certificate was presented on the Holder-of-key endpoint [{}]", token.getLogString());
      throw new SamlErrorStatusException(SamlErrorStatus.HOLDER_OF_KEY_NO_CERTIFICATE,
          SamlErrorStatus.HOLDER_OF_KEY_NO_CERTIFICATE_MESSAGE_CODE,
          "No client certificate was presented on the Holder-of-key endpoint");
    }

    // Is the Service Provider accepted?
    //
    final boolean accepted;
    try {
      accepted = this.requesterAcceptance.isAccepted(record, this.clientRegistry);
    }
    catch (final ClientRegistryException e) {
      log.error("The client registry failed during the requester acceptance check - {} [{}]",
          e.getMessage(), token.getLogString(), e);
      throw new UnrecoverableErrorException(SamlUnrecoverableError.PEER_LOOKUP_FAILED,
          "The client registry failed during the requester acceptance check", e);
    }
    if (!accepted) {
      log.info("SP is not accepted by the requester acceptance check [{}]", token.getLogString());
      throw new SamlErrorStatusException(SamlErrorStatus.of(AuthenticationError.NOT_AUTHORIZED),
          AuthenticationError.NOT_AUTHORIZED.getMessageCode(), AuthenticationError.NOT_AUTHORIZED.getDefaultMessage());
    }

    // Check the requested NameIDPolicy, and if correct, set up a NameIDGenerator ...
    //
    final NameIDGenerator nameIdGenerator =
        this.nameIdGeneratorFactory.getNameIDGenerator(token.getAuthnRequest(), peerMetadata);

    final SamlAuthenticationRequirements requirements = this.createAuthenticationRequirements(token);
    log.debug("Authentication requirements: {} [{}]", requirements, token.getLogString());

    final Saml2AuthnRequestData requestData = new Saml2AuthnRequestData(
        new SerializableOpenSamlObject<>(token.getAuthnRequest()),
        responseAttributes, token.isHolderOfKey(), nameIdGenerator, token.getClientCertificate());

    final UserAuthenticationInputToken inputToken = new UserAuthenticationInputToken(requirements,
        record.requester(), token.getAuthnRequest().getID(), requestData);
    inputToken.setAuditData(AuditFlowData.of(AuditRequester.of(record, true), Saml2AuditData.authnRequest(token)));

    // The OpenSAML context and the HTTP request are no longer needed ...
    //
    token.setMessageContext(null);
    token.setHttpServletRequest(null);
    token.setAuthenticated(true);

    return inputToken;
  }

  /**
   * Supports {@link Saml2AuthnRequestAuthenticationToken}.
   */
  @Override
  public boolean supports(final @NonNull Class<?> authentication) {
    return Saml2AuthnRequestAuthenticationToken.class.isAssignableFrom(authentication);
  }

  /**
   * Creates the authentication requirements of the request.
   *
   * @param token the authentication request token
   * @return the authentication requirements
   * @throws SamlErrorStatusException for errors that are reported to the Service Provider
   */
  protected @NonNull SamlAuthenticationRequirements createAuthenticationRequirements(
      final @NonNull Saml2AuthnRequestAuthenticationToken token) throws SamlErrorStatusException {

    final AuthnRequest authnRequest = token.getAuthnRequest();
    final EntityDescriptor peerMetadata = Objects.requireNonNull(token.getPeerMetadata());

    final boolean forceAuthn = Boolean.TRUE.equals(authnRequest.isForceAuthn());
    final boolean isPassive = Boolean.TRUE.equals(authnRequest.isPassive());
    if (forceAuthn && isPassive) {
      throw invalid("ForceAuthn and IsPassive cannot both be set", token);
    }

    final SamlAuthenticationRequirements requirements = new SamlAuthenticationRequirements();
    requirements.setForceAuthn(forceAuthn);
    requirements.setPassiveAuthn(isPassive);
    requirements.setEntityCategories(EntityDescriptorUtils.getEntityCategories(peerMetadata));
    requirements.setRequestedAttributes(
        this.requestedAttributeResolver.resolve(new RequestedAttributeContext(authnRequest, peerMetadata)));
    requirements.setAuthnContextRequirements(
        this.authnContextResolver.resolve(authnRequest.getRequestedAuthnContext(), token.getLogString()));

    final Scoping scoping = authnRequest.getScoping();
    if (scoping != null) {
      if (scoping.getIDPList() != null) {
        requirements.setRequestedAuthnProviders(scoping.getIDPList().getIDPEntrys().stream()
            .map(IDPEntry::getProviderID)
            .filter(StringUtils::hasText)
            .toList());
      }
      requirements.setOriginalRequesters(scoping.getRequesterIDs().stream()
          .map(RequesterID::getURI)
          .filter(StringUtils::hasText)
          .map(OriginalRequester::of)
          .toList());
    }

    if (this.signMessageExtractor != null) {
      requirements.setSignMessage(this.signMessageExtractor.extract(token));
    }
    requirements.setUserMessage(this.extractUserMessage(token));
    requirements.setSadRequestExtension(this.extractSadRequest(token));

    return requirements;
  }

  /**
   * Extracts the {@code UserMessage} extension. A message with a MIME type that is not supported is an error if user
   * messages are supported, and is otherwise ignored.
   *
   * @param token the authentication request token
   * @return the user message, or {@code null}
   * @throws SamlErrorStatusException for an invalid user message, when user messages are supported
   */
  private @Nullable GenericUserMessage extractUserMessage(final @NonNull Saml2AuthnRequestAuthenticationToken token)
      throws SamlErrorStatusException {

    final UserMessage userMessage = Optional.ofNullable(token.getAuthnRequest().getExtensions())
        .map(e -> e.getUnknownXMLObjects(UserMessage.DEFAULT_ELEMENT_NAME))
        .filter(list -> !list.isEmpty())
        .map(list -> list.get(0))
        .filter(UserMessage.class::isInstance)
        .map(UserMessage.class::cast)
        .orElse(null);
    if (userMessage == null) {
      return null;
    }
    try {
      final List<LocalizedMessage> messages = new ArrayList<>();
      for (final Message message : userMessage.getMessages()) {
        if (StringUtils.hasText(message.getValue())) {
          messages.add(new LocalizedMessage(message.getXMLLang(), message.getValue().replaceAll("\\s", "")));
        }
      }
      if (messages.isEmpty()) {
        log.debug("UserMessage extension holds no messages - ignoring [{}]", token.getLogString());
        return null;
      }
      final GenericUserMessage result =
          new GenericUserMessage(messages, MessageMimeType.parse(userMessage.getMimeType()));
      log.debug("UserMessage extension present for languages {} [{}]",
          messages.stream().map(LocalizedMessage::language).toList(), token.getLogString());
      return result;
    }
    catch (final IllegalArgumentException e) {
      log.info("Invalid UserMessage extension - {} [{}]", e.getMessage(), token.getLogString());
      if (this.supportsUserMessage) {
        throw new SamlErrorStatusException(SamlErrorStatus.INVALID_USER_MESSAGE,
            SamlErrorStatus.INVALID_USER_MESSAGE_MESSAGE_CODE, "Invalid UserMessage extension - " + e.getMessage(),
            e);
      }
      return null;
    }
  }

  /**
   * Extracts and validates the {@code SADRequest} extension. It is only accepted from signature services, and is
   * ignored for other Service Providers.
   *
   * @param token the authentication request token
   * @return the SAD request, or {@code null}
   * @throws SamlErrorStatusException for an invalid SAD request
   */
  private @Nullable SadRequestExtension extractSadRequest(final @NonNull Saml2AuthnRequestAuthenticationToken token)
      throws SamlErrorStatusException {

    final SADRequest sadRequest = Optional.ofNullable(token.getAuthnRequest().getExtensions())
        .map(e -> e.getUnknownXMLObjects(SADRequest.DEFAULT_ELEMENT_NAME))
        .filter(list -> !list.isEmpty())
        .map(list -> list.get(0))
        .filter(SADRequest.class::isInstance)
        .map(SADRequest.class::cast)
        .orElse(null);
    if (sadRequest == null) {
      return null;
    }
    if (!token.isSignatureServicePeer()) {
      log.info("Received SADRequest from an SP that is not a signature service - ignoring [{}]",
          token.getLogString());
      return null;
    }
    if (sadRequest.getID() == null) {
      throw invalid("SADRequest extension lacks ID field", token);
    }
    if (sadRequest.getRequestedVersion() != null && !SADVersion.VERSION_10.equals(sadRequest.getRequestedVersion())) {
      throw invalid("SADRequest extension has unsupported SAD version", token);
    }
    if (sadRequest.getDocCount() == null) {
      throw invalid("SADRequest extension lacks DocCount field", token);
    }
    if (sadRequest.getRequesterID() == null) {
      throw invalid("SADRequest extension lacks RequesterID field", token);
    }
    if (!sadRequest.getRequesterID().equals(token.getEntityId())) {
      throw invalid("SADRequest extension has RequesterID field that does not match SP entityID", token);
    }
    if (sadRequest.getSignRequestID() == null) {
      throw invalid("SADRequest extension lacks SignRequestID field", token);
    }
    return new SadRequestExtension(sadRequest);
  }

  /**
   * Creates the exception for an invalid request, and logs it.
   *
   * @param reason the reason
   * @param token the authentication request token
   * @return a {@link SamlErrorStatusException}
   */
  private static @NonNull SamlErrorStatusException invalid(final @NonNull String reason,
      final @NonNull Saml2AuthnRequestAuthenticationToken token) {
    final String msg = "Invalid AuthnRequest - " + reason;
    log.info("{} [{}]", msg, token.getLogString());
    return new SamlErrorStatusException(SamlErrorStatus.INVALID_REQUEST, SamlErrorStatus.INVALID_REQUEST_MESSAGE_CODE,
        msg);
  }

}
