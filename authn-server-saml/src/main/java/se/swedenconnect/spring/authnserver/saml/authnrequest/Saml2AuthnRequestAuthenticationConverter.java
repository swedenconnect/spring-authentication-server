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

import jakarta.servlet.http.HttpServletRequest;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Objects;
import java.util.Optional;

import net.shibboleth.shared.component.ComponentInitializationException;
import org.jspecify.annotations.NonNull;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.saml.common.binding.BindingDescriptor;
import org.opensaml.saml.common.binding.SAMLBindingSupport;
import org.opensaml.saml.common.binding.decoding.SAMLMessageDecoder;
import org.opensaml.saml.common.binding.security.impl.MessageLifetimeSecurityHandler;
import org.opensaml.saml.common.binding.security.impl.ReceivedEndpointSecurityHandler;
import org.opensaml.saml.common.messaging.context.SAMLMetadataContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.messaging.context.SAMLProtocolContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPPostDecoder;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPRedirectDeflateDecoder;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml.saml2.metadata.SPSSODescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.error.CommonUnrecoverableError;
import se.swedenconnect.spring.authnserver.error.UnrecoverableErrorException;
import se.swedenconnect.spring.authnserver.registry.ClientRegistry;
import se.swedenconnect.spring.authnserver.registry.ClientRegistryException;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;
import se.swedenconnect.spring.authnserver.saml.error.SamlUnrecoverableError;

/**
 * Decodes a SAML authentication request received with the redirect or the POST binding, checks its format, where it
 * was delivered and its age, and looks up the Service Provider that sent it in the {@link ClientRegistry}.
 * <p>
 * Every failure here is unrecoverable, since the Service Provider, or where to send a response, is not yet known.
 * </p>
 *
 * @author Martin Lindström
 */
public class Saml2AuthnRequestAuthenticationConverter implements AuthenticationConverter {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(Saml2AuthnRequestAuthenticationConverter.class);

  /** The request attribute holding the certificates that the client presented in the TLS handshake. */
  public static final String CLIENT_CERTIFICATE_ATTRIBUTE = "jakarta.servlet.request.X509Certificate";

  /** The default maximum age of a received message, 3 minutes. */
  public static final Duration DEFAULT_MAX_MESSAGE_AGE = Duration.ofMinutes(3);

  /** The client registry where the Service Provider is looked up. */
  private final ClientRegistry clientRegistry;

  /** Tells whether a request was received on a Holder-of-key endpoint. */
  private final RequestMatcher holderOfKeyMatcher;

  /** Binding descriptor for redirect. */
  private final BindingDescriptor redirectBindingDescriptor;

  /** Binding descriptor for POST. */
  private final BindingDescriptor postBindingDescriptor;

  /** The allowed clock skew. */
  private final Duration clockSkew;

  /** The maximum age of a received message. */
  private final Duration maxMessageAge;

  /**
   * Constructor.
   *
   * @param clientRegistry the client registry where the Service Provider is looked up
   * @param holderOfKeyMatcher tells whether a request was received on a Holder-of-key endpoint
   * @param clockSkew the allowed clock skew
   * @param maxMessageAge the maximum age of a received message
   */
  public Saml2AuthnRequestAuthenticationConverter(final @NonNull ClientRegistry clientRegistry,
      final @NonNull RequestMatcher holderOfKeyMatcher, final @NonNull Duration clockSkew,
      final @NonNull Duration maxMessageAge) {
    this.clientRegistry = Objects.requireNonNull(clientRegistry, "clientRegistry must not be null");
    this.holderOfKeyMatcher = Objects.requireNonNull(holderOfKeyMatcher, "holderOfKeyMatcher must not be null");
    this.clockSkew = Objects.requireNonNull(clockSkew, "clockSkew must not be null");
    this.maxMessageAge = Objects.requireNonNull(maxMessageAge, "maxMessageAge must not be null");
    try {
      this.redirectBindingDescriptor = new BindingDescriptor();
      this.redirectBindingDescriptor.setId(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
      this.redirectBindingDescriptor.setShortName("Redirect");
      this.redirectBindingDescriptor.setSignatureCapable(true);
      this.redirectBindingDescriptor.initialize();

      this.postBindingDescriptor = new BindingDescriptor();
      this.postBindingDescriptor.setId(SAMLConstants.SAML2_POST_BINDING_URI);
      this.postBindingDescriptor.setShortName("POST");
      this.postBindingDescriptor.initialize();
    }
    catch (final ComponentInitializationException e) {
      throw new IllegalArgumentException("Failed to initialize OpenSAML binding descriptors", e);
    }
  }

  /**
   * Decodes the request and looks up the Service Provider.
   *
   * @param request the HTTP request
   * @return a {@link Saml2AuthnRequestAuthenticationToken}
   * @throws UnrecoverableErrorException if the request cannot be processed
   */
  @Override
  public @NonNull Saml2AuthnRequestAuthenticationToken convert(final @NonNull HttpServletRequest request)
      throws UnrecoverableErrorException {

    final MessageContext msgContext;
    try {
      final SAMLMessageDecoder decoder = this.getDecoder(request);
      decoder.decode();
      msgContext = decoder.getMessageContext();
    }
    catch (final MessageDecodingException e) {
      log.info("Unable to decode incoming authentication request - {}", e.getMessage());
      log.debug("", e);
      throw new UnrecoverableErrorException(SamlUnrecoverableError.FAILED_DECODE,
          "Unable to decode incoming authentication request", e);
    }

    if (!(msgContext.getMessage() instanceof final AuthnRequest authnRequest)) {
      log.info("Incoming request is not a SAML V2 AuthnRequest message");
      throw new UnrecoverableErrorException(SamlUnrecoverableError.INVALID_AUTHNREQUEST_FORMAT,
          "Incoming request is not a SAML V2 AuthnRequest message");
    }
    final String bindingUri = "GET".equals(request.getMethod())
        ? SAMLConstants.SAML2_REDIRECT_BINDING_URI
        : SAMLConstants.SAML2_POST_BINDING_URI;

    final Saml2AuthnRequestAuthenticationToken token = new Saml2AuthnRequestAuthenticationToken(authnRequest,
        SAMLBindingSupport.getRelayState(msgContext), bindingUri, this.holderOfKeyMatcher.matches(request));
    token.setMessageContext(msgContext);
    token.setHttpServletRequest(request);
    if (token.isHolderOfKey()
        && request.getAttribute(CLIENT_CERTIFICATE_ATTRIBUTE) instanceof final X509Certificate[] certificates
        && certificates.length > 0) {
      token.setClientCertificate(certificates[0]);
    }

    final SAMLProtocolContext protocolContext = new SAMLProtocolContext();
    protocolContext.setProtocol(SAMLConstants.SAML20P_NS);
    msgContext.addSubcontext(protocolContext);

    // Check version, ID and issuer ...
    //
    if (authnRequest.getVersion() == null || authnRequest.getVersion().getMajorVersion() != 2) {
      log.info("Unsupported version on AuthnRequest message [{}]", token.getLogString());
      throw new UnrecoverableErrorException(SamlUnrecoverableError.INVALID_AUTHNREQUEST_FORMAT,
          "Unsupported version on AuthnRequest message");
    }
    if (!StringUtils.hasText(authnRequest.getID())) {
      log.info("Missing ID on received AuthnRequest message [{}]", token.getLogString());
      throw new UnrecoverableErrorException(SamlUnrecoverableError.INVALID_AUTHNREQUEST_FORMAT,
          "Missing ID on received AuthnRequest message");
    }
    final String peerEntityId = Optional.ofNullable(authnRequest.getIssuer())
        .map(Issuer::getValue)
        .filter(StringUtils::hasText)
        .orElseThrow(() -> {
          log.info("Missing issuer of received AuthnRequest message [{}]", token.getLogString());
          return new UnrecoverableErrorException(SamlUnrecoverableError.INVALID_AUTHNREQUEST_FORMAT,
              "Missing issuer of received AuthnRequest message");
        });

    // Check the receiver endpoint against the Destination of the message, and the age of the message ...
    //
    try {
      final ReceivedEndpointSecurityHandler endpointHandler = new ReceivedEndpointSecurityHandler();
      endpointHandler.setHttpServletRequestSupplier(() -> request);
      endpointHandler.initialize();
      endpointHandler.invoke(msgContext);
    }
    catch (final MessageHandlerException e) {
      log.info("Receiver endpoint check failed: {} [{}]", e.getMessage(), token.getLogString());
      throw new UnrecoverableErrorException(SamlUnrecoverableError.ENDPOINT_CHECK_FAILURE,
          "Receiver endpoint check failed: " + e.getMessage(), e);
    }
    catch (final ComponentInitializationException e) {
      throw new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL,
          "Failed to initialize endpoint security handler", e);
    }
    try {
      final MessageLifetimeSecurityHandler lifetimeHandler = new MessageLifetimeSecurityHandler();
      lifetimeHandler.setRequiredRule(true);
      lifetimeHandler.setClockSkew(this.clockSkew);
      lifetimeHandler.setMessageLifetime(this.maxMessageAge);
      lifetimeHandler.initialize();
      lifetimeHandler.invoke(msgContext);
    }
    catch (final MessageHandlerException e) {
      log.info("Message lifetime check failed: {} [{}]", e.getMessage(), token.getLogString());
      throw new UnrecoverableErrorException(SamlUnrecoverableError.MESSAGE_TOO_OLD,
          "Message lifetime check failed: " + e.getMessage(), e);
    }
    catch (final ComponentInitializationException e) {
      throw new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL,
          "Failed to initialize lifetime security handler", e);
    }

    // Look up the Service Provider ...
    //
    final RequesterRecord record;
    try {
      record = this.clientRegistry.lookup(AuthenticationProtocol.SAML, peerEntityId);
    }
    catch (final ClientRegistryException e) {
      log.error("Failed to look up SP in the client registry - {} [{}]", e.getMessage(), token.getLogString(), e);
      throw new UnrecoverableErrorException(SamlUnrecoverableError.PEER_LOOKUP_FAILED,
          "Failed to look up SP in the client registry", e);
    }
    final EntityDescriptor spMetadata = Optional.ofNullable(record)
        .map(r -> r.getProtocolMetadata(EntityDescriptor.class))
        .filter(md -> md.getSPSSODescriptor(SAMLConstants.SAML20P_NS) != null)
        .orElseThrow(() -> {
          log.info("SP is not known - no valid SAML metadata found [{}]", token.getLogString());
          return new UnrecoverableErrorException(SamlUnrecoverableError.UNKNOWN_PEER,
              "Failed to look up valid SAML metadata for SP " + peerEntityId);
        });
    log.debug("SAML metadata for SP successfully found [{}]", token.getLogString());

    // In order to avoid several threads working with the same DOM, the descriptor is cloned ...
    //
    final EntityDescriptor clonedMetadata;
    try {
      clonedMetadata = XMLObjectSupport.cloneXMLObject(spMetadata);
    }
    catch (final MarshallingException | UnmarshallingException e) {
      throw new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL, "Failed to clone SP metadata", e);
    }
    token.setPeerMetadata(clonedMetadata);
    token.setRequesterRecord(Objects.requireNonNull(record));

    final SAMLPeerEntityContext peerContext = new SAMLPeerEntityContext();
    peerContext.setEntityId(clonedMetadata.getEntityID());
    peerContext.setAuthenticated(false);
    peerContext.setRole(SPSSODescriptor.DEFAULT_ELEMENT_NAME);
    msgContext.addSubcontext(peerContext);

    final SAMLMetadataContext mdContext = new SAMLMetadataContext();
    mdContext.setEntityDescriptor(clonedMetadata);
    mdContext.setRoleDescriptor(clonedMetadata.getSPSSODescriptor(SAMLConstants.SAML20P_NS));
    peerContext.addSubcontext(mdContext);

    return token;
  }

  /**
   * Gets a decoder for the binding of the request.
   *
   * @param request the HTTP request
   * @return a {@link SAMLMessageDecoder}
   * @throws UnrecoverableErrorException for unsupported HTTP methods
   */
  protected @NonNull SAMLMessageDecoder getDecoder(final @NonNull HttpServletRequest request) {
    try {
      if ("GET".equals(request.getMethod())) {
        final HTTPRedirectDeflateDecoder decoder = new HTTPRedirectDeflateDecoder();
        decoder.setBindingDescriptor(this.redirectBindingDescriptor);
        decoder.setHttpServletRequestSupplier(() -> request);
        decoder.setParserPool(Objects.requireNonNull(XMLObjectProviderRegistrySupport.getParserPool()));
        decoder.initialize();
        return decoder;
      }
      else if ("POST".equals(request.getMethod())) {
        final HTTPPostDecoder decoder = new HTTPPostDecoder();
        decoder.setBindingDescriptor(this.postBindingDescriptor);
        decoder.setHttpServletRequestSupplier(() -> request);
        decoder.setParserPool(Objects.requireNonNull(XMLObjectProviderRegistrySupport.getParserPool()));
        decoder.initialize();
        return decoder;
      }
      else {
        throw new UnrecoverableErrorException(SamlUnrecoverableError.FAILED_DECODE,
            "Unsupported HTTP method - " + request.getMethod());
      }
    }
    catch (final ComponentInitializationException e) {
      throw new UnrecoverableErrorException(CommonUnrecoverableError.INTERNAL, "Failed to create decoder", e);
    }
  }

}
