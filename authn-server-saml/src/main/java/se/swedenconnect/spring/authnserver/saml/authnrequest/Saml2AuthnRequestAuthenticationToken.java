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

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;
import jakarta.servlet.http.HttpServletRequest;

import java.io.Serial;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.springframework.security.authentication.AbstractAuthenticationToken;

import se.swedenconnect.opensaml.common.utils.SerializableOpenSamlObject;
import se.swedenconnect.opensaml.saml2.metadata.EntityDescriptorUtils;
import se.swedenconnect.opensaml.sweid.saml2.metadata.entitycategory.EntityCategoryConstants;
import se.swedenconnect.spring.authnserver.LibraryVersion;
import se.swedenconnect.spring.authnserver.registry.RequesterRecord;

/**
 * A SAML authentication request while it is being processed: the decoded {@code AuthnRequest}, the metadata of the
 * Service Provider that sent it, and what the processing has established so far.
 *
 * @author Martin Lindström
 */
public class Saml2AuthnRequestAuthenticationToken extends AbstractAuthenticationToken {

  @Serial
  private static final long serialVersionUID = LibraryVersion.SERIAL_VERSION_UID;

  /** The authentication request. */
  private final SerializableOpenSamlObject<AuthnRequest> authnRequest;

  /** The relay state. */
  private final String relayState;

  /** The binding that the request was received with. */
  private final String bindingUri;

  /** Whether the request was received on a Holder-of-key endpoint. */
  private final boolean holderOfKey;

  /** The certificate that the client presented in the TLS handshake, for Holder-of-key. */
  private X509Certificate clientCertificate;

  /** The metadata of the Service Provider. */
  private SerializableOpenSamlObject<EntityDescriptor> peerMetadata;

  /** The record of the Service Provider in the client registry. */
  private transient RequesterRecord requesterRecord;

  /** The URL of the assertion consumer service that the response is sent to. */
  private String assertionConsumerServiceUrl;

  /** The OpenSAML message context, used during the processing only. */
  private transient MessageContext messageContext;

  /** The HTTP request, used during the processing only. */
  private transient HttpServletRequest httpServletRequest;

  /**
   * Constructor.
   *
   * @param authnRequest the authentication request
   * @param relayState the relay state, or {@code null}
   * @param bindingUri the binding that the request was received with
   * @param holderOfKey whether the request was received on a Holder-of-key endpoint
   */
  public Saml2AuthnRequestAuthenticationToken(final @Nonnull AuthnRequest authnRequest,
      final @Nullable String relayState, final @Nonnull String bindingUri, final boolean holderOfKey) {
    super(List.of());
    this.authnRequest = new SerializableOpenSamlObject<>(
        Objects.requireNonNull(authnRequest, "authnRequest must not be null"));
    this.relayState = relayState;
    this.bindingUri = Objects.requireNonNull(bindingUri, "bindingUri must not be null");
    this.holderOfKey = holderOfKey;
    this.setAuthenticated(false);
  }

  /** {@inheritDoc} */
  @Override
  public @Nonnull Object getCredentials() {
    return "";
  }

  /**
   * Gets the entityID of the Service Provider.
   */
  @Override
  public @Nullable Object getPrincipal() {
    return this.getEntityId();
  }

  /**
   * Gets the entityID of the Service Provider, as given by the {@code Issuer} of the request.
   *
   * @return the entityID, or {@code null} if the request has no issuer
   */
  public @Nullable String getEntityId() {
    return Optional.ofNullable(this.getAuthnRequest().getIssuer()).map(Issuer::getValue).orElse(null);
  }

  /**
   * Gets the authentication request.
   *
   * @return the authentication request
   */
  public @Nonnull AuthnRequest getAuthnRequest() {
    return this.authnRequest.get();
  }

  /**
   * Gets the relay state.
   *
   * @return the relay state, or {@code null}
   */
  public @Nullable String getRelayState() {
    return this.relayState;
  }

  /**
   * Gets the binding that the request was received with.
   *
   * @return the binding URI
   */
  public @Nonnull String getBindingUri() {
    return this.bindingUri;
  }

  /**
   * Tells whether the request was received on a Holder-of-key endpoint.
   *
   * @return {@code true} for Holder-of-key and {@code false} otherwise
   */
  public boolean isHolderOfKey() {
    return this.holderOfKey;
  }

  /**
   * Gets the certificate that the client presented in the TLS handshake. It is only read for a request received on a
   * Holder-of-key endpoint.
   *
   * @return the client certificate, or {@code null} if none was presented
   */
  public @Nullable X509Certificate getClientCertificate() {
    return this.clientCertificate;
  }

  /**
   * Assigns the certificate that the client presented in the TLS handshake.
   *
   * @param clientCertificate the client certificate
   */
  public void setClientCertificate(final @Nullable X509Certificate clientCertificate) {
    this.clientCertificate = clientCertificate;
  }

  /**
   * Gets the metadata of the Service Provider.
   *
   * @return the metadata, or {@code null} if the Service Provider has not been found yet
   */
  public @Nullable EntityDescriptor getPeerMetadata() {
    return Optional.ofNullable(this.peerMetadata).map(SerializableOpenSamlObject::get).orElse(null);
  }

  /**
   * Assigns the metadata of the Service Provider.
   *
   * @param peerMetadata the metadata
   */
  public void setPeerMetadata(final @Nonnull EntityDescriptor peerMetadata) {
    this.peerMetadata = new SerializableOpenSamlObject<>(peerMetadata);
  }

  /**
   * Gets the record of the Service Provider in the client registry.
   *
   * @return the record, or {@code null} if the Service Provider has not been found yet
   */
  public @Nullable RequesterRecord getRequesterRecord() {
    return this.requesterRecord;
  }

  /**
   * Assigns the record of the Service Provider in the client registry.
   *
   * @param requesterRecord the record
   */
  public void setRequesterRecord(final @Nonnull RequesterRecord requesterRecord) {
    this.requesterRecord = requesterRecord;
  }

  /**
   * Tells whether the Service Provider is a signature service, that is, whether it declares the signature service
   * entity category.
   *
   * @return {@code true} for a signature service and {@code false} otherwise
   */
  public boolean isSignatureServicePeer() {
    return Optional.ofNullable(this.getPeerMetadata())
        .map(EntityDescriptorUtils::getEntityCategories)
        .filter(c -> c.contains(EntityCategoryConstants.SERVICE_TYPE_CATEGORY_SIGSERVICE.getUri()))
        .isPresent();
  }

  /**
   * Gets the URL of the assertion consumer service that the response is sent to.
   *
   * @return the URL, or {@code null} if it has not been established yet
   */
  public @Nullable String getAssertionConsumerServiceUrl() {
    return this.assertionConsumerServiceUrl;
  }

  /**
   * Assigns the URL of the assertion consumer service that the response is sent to.
   *
   * @param assertionConsumerServiceUrl the URL
   */
  public void setAssertionConsumerServiceUrl(final @Nonnull String assertionConsumerServiceUrl) {
    this.assertionConsumerServiceUrl =
        Objects.requireNonNull(assertionConsumerServiceUrl, "assertionConsumerServiceUrl must not be null");
  }

  /**
   * Gets the OpenSAML message context.
   *
   * @return the message context, or {@code null} once the processing is done
   */
  public @Nullable MessageContext getMessageContext() {
    return this.messageContext;
  }

  /**
   * Assigns the OpenSAML message context.
   *
   * @param messageContext the message context
   */
  public void setMessageContext(final @Nullable MessageContext messageContext) {
    this.messageContext = messageContext;
  }

  /**
   * Gets the HTTP request that carried the authentication request.
   *
   * @return the HTTP request, or {@code null} once the processing is done
   */
  public @Nullable HttpServletRequest getHttpServletRequest() {
    return this.httpServletRequest;
  }

  /**
   * Assigns the HTTP request that carried the authentication request.
   *
   * @param httpServletRequest the HTTP request
   */
  public void setHttpServletRequest(final @Nullable HttpServletRequest httpServletRequest) {
    this.httpServletRequest = httpServletRequest;
  }

  /**
   * Gets a string for log lines about the request.
   *
   * @return the log string
   */
  public @Nonnull String getLogString() {
    return "entity-id: '%s', authn-request: '%s'".formatted(
        Optional.ofNullable(this.getEntityId()).orElse("unknown"),
        Optional.ofNullable(this.getAuthnRequest().getID()).orElse("unknown"));
  }

}
