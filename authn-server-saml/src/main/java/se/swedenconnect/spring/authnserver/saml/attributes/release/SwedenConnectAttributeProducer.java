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
package se.swedenconnect.spring.authnserver.saml.attributes.release;

import jakarta.annotation.Nonnull;
import jakarta.annotation.Nullable;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Objects;

import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.saml2.core.Attribute;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import se.swedenconnect.opensaml.saml2.attribute.AttributeUtils;
import se.swedenconnect.opensaml.sweid.saml2.signservice.SADFactory;
import se.swedenconnect.opensaml.sweid.saml2.signservice.SADFactory.SADBuilder;
import se.swedenconnect.opensaml.sweid.saml2.signservice.SignMessageDigestIssuer;
import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.Message;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.release.DefaultAttributeProducer;
import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.error.AuthenticationError;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.message.GenericSignMessage;
import se.swedenconnect.spring.authnserver.message.LocalizedMessage;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlAttributeMapping;
import se.swedenconnect.spring.authnserver.saml.authentication.SadRequestExtension;
import se.swedenconnect.spring.authnserver.saml.authentication.SamlAuthenticationRequirements;

/**
 * An attribute producer that adds the attributes of the
 * <a href="https://docs.swedenconnect.se/technical-framework/">Technical Specifications for the Swedish eID
 * Framework</a> to what the default producer releases.
 * <p>
 * Two attributes are added, both of them about the authentication event rather than about the user:
 * </p>
 * <ul>
 * <li>{@link AttributeIdentifiers#SIGN_MESSAGE_DIGEST}, released when the request carried a sign message and the
 * message was displayed for the user. It is the proof that the user saw and approved the message, see Section 3.2.4
 * of <a href=
 * "https://docs.swedenconnect.se/technical-framework/latest/04_-_Attribute_Specification_for_the_Swedish_eID_Framework.html">Attribute
 * Specification for the Swedish eID Framework</a>. If the digest cannot be built and the sign message had to be
 * shown, the authentication fails with {@link AuthenticationError#SIGN_MESSAGE_NOT_DISPLAYED}. If it did not have to
 * be shown, the digest is left out.</li>
 * <li>{@link AttributeIdentifiers#SAD}, the Signature Activation Data, released together with the sign message digest
 * when the request carried a {@code SADRequest} and a {@link SADFactory} has been assigned.</li>
 * </ul>
 *
 * @author Martin Lindström
 */
public class SwedenConnectAttributeProducer extends DefaultAttributeProducer {

  /** Logger. */
  private static final Logger log = LoggerFactory.getLogger(SwedenConnectAttributeProducer.class);

  /** Calculates the sign message digest. */
  private SignMessageDigestIssuer signMessageDigestIssuer = new SignMessageDigestIssuer();

  /** Gives the SAML attribute name of the user's primary attribute, which the SAD records. */
  private SamlAttributeMapping attributeMapping = new SamlAttributeMapping();

  /** Creates the Signature Activation Data. */
  private SADFactory sadFactory;

  /**
   * Releases the requested attributes, the sign message digest and the SAD.
   */
  @Override
  public @Nonnull List<GenericAttribute<? extends Serializable>> releaseAttributes(
      final @Nonnull UserAuthentication userAuthentication) {

    final List<GenericAttribute<? extends Serializable>> released =
        new ArrayList<>(super.releaseAttributes(userAuthentication));

    final GenericAttribute<String> signMessageDigest = this.releaseSignMessageDigest(userAuthentication);
    if (signMessageDigest != null) {
      released.add(signMessageDigest);

      final GenericAttribute<String> sad = this.releaseSad(userAuthentication);
      if (sad != null) {
        released.add(sad);
      }
    }
    return released;
  }

  /**
   * Assigns the mapping used to find the SAML attribute name of the user's primary attribute, which is recorded in the
   * SAD. It defaults to the built-in mapping.
   *
   * @param attributeMapping a {@link SamlAttributeMapping}
   */
  public void setAttributeMapping(final @Nonnull SamlAttributeMapping attributeMapping) {
    this.attributeMapping = Objects.requireNonNull(attributeMapping, "attributeMapping must not be null");
  }

  /**
   * Assigns the issuer that calculates the sign message digest. It defaults to an issuer using the SHA-256 digest
   * algorithm, which the Attribute Specification for the Swedish eID Framework requires unless the Service Provider
   * has declared another algorithm as preferred.
   *
   * @param signMessageDigestIssuer a {@link SignMessageDigestIssuer}
   */
  public void setSignMessageDigestIssuer(final @Nonnull SignMessageDigestIssuer signMessageDigestIssuer) {
    this.signMessageDigestIssuer =
        Objects.requireNonNull(signMessageDigestIssuer, "signMessageDigestIssuer must not be null");
  }

  /**
   * Gets the factory that creates the Signature Activation Data.
   *
   * @return a {@link SADFactory}, or {@code null} if none has been assigned
   */
  public @Nullable SADFactory getSadFactory() {
    return this.sadFactory;
  }

  /**
   * Assigns the factory that creates the Signature Activation Data. Without it no SAD is released.
   *
   * @param sadFactory a {@link SADFactory}
   */
  public void setSadFactory(final @Nullable SADFactory sadFactory) {
    this.sadFactory = sadFactory;
  }

  /**
   * Builds the sign message digest attribute.
   *
   * @param userAuthentication the authentication result
   * @return the attribute, or {@code null} if it is not to be released
   * @throws AuthenticationErrorException if the digest cannot be built and the sign message had to be shown
   */
  private @Nullable GenericAttribute<String> releaseSignMessageDigest(
      final @Nonnull UserAuthentication userAuthentication) {

    final AuthenticationRequirements requirements = userAuthentication.getAuthnRequirements();
    final GenericSignMessage signMessage = requirements != null ? requirements.getSignMessage() : null;
    if (signMessage == null) {
      return null;
    }
    final AuthenticatedUser user = userAuthentication.getAuthenticatedUser();
    if (!user.isSignMessageDisplayed()) {
      log.debug("No sign message was displayed - no {} is released [{}]",
          AttributeIdentifiers.SIGN_MESSAGE_DIGEST, userAuthentication.getLogString());
      return null;
    }
    try {
      final Message message = (Message) XMLObjectSupport.buildXMLObject(Message.DEFAULT_ELEMENT_NAME);
      message.setValue(Base64.getEncoder().encodeToString(
          displayedText(signMessage, user.getSignMessageLanguage()).getBytes(StandardCharsets.UTF_8)));

      final Attribute attribute = this.signMessageDigestIssuer.create(message);
      final String digest = AttributeUtils.getAttributeStringValue(attribute);
      if (digest == null) {
        throw new IllegalArgumentException("No digest value was produced");
      }
      return GenericAttribute.of(AttributeIdentifiers.SIGN_MESSAGE_DIGEST, digest);
    }
    catch (final Exception e) {
      final String msg = "Failed to construct signMessageDigest - %s".formatted(e.getMessage());
      log.info("{} [{}]", msg, userAuthentication.getLogString(), e);
      if (signMessage.isMustShow()) {
        throw new AuthenticationErrorException(AuthenticationError.SIGN_MESSAGE_NOT_DISPLAYED, msg);
      }
      return null;
    }
  }

  /**
   * Builds the SAD attribute.
   *
   * @param userAuthentication the authentication result
   * @return the attribute, or {@code null} if it is not to be released
   */
  private @Nullable GenericAttribute<String> releaseSad(final @Nonnull UserAuthentication userAuthentication) {

    if (!(userAuthentication.getAuthnRequirements() instanceof final SamlAuthenticationRequirements requirements)) {
      return null;
    }
    final SadRequestExtension sadRequest = requirements.getSadRequestExtension();
    if (sadRequest == null) {
      return null;
    }
    if (this.sadFactory == null) {
      log.debug("No SAD factory has been assigned - no {} is released [{}]",
          AttributeIdentifiers.SAD, userAuthentication.getLogString());
      return null;
    }
    final AuthenticatedUser user = userAuthentication.getAuthenticatedUser();
    final String userIdAttributeName = this.samlNameOfPrimaryAttribute(user);
    final SADBuilder builder = userIdAttributeName != null
        ? this.sadFactory.getBuilder(userIdAttributeName)
        : this.sadFactory.getBuilder();
    try {
      builder.subject(user.getUsername())
          .audience(sadRequest.getRequesterId())
          .inResponseTo(sadRequest.getId())
          .loa(user.getAuthnContextUri())
          .requestID(sadRequest.getSignRequestId());
      if (sadRequest.getDocumentCount() != null) {
        builder.numberOfDocuments(sadRequest.getDocumentCount());
      }
      return GenericAttribute.of(AttributeIdentifiers.SAD, builder.buildJwt());
    }
    catch (final Exception e) {
      log.info("Failed to construct sad attribute [{}]", userAuthentication.getLogString(), e);
      return null;
    }
  }

  /**
   * Gets the SAML attribute name of the user's primary attribute.
   *
   * @param user the authenticated user
   * @return the SAML attribute name, or {@code null} if the attribute has no SAML mapping
   */
  private @Nullable String samlNameOfPrimaryAttribute(final @Nonnull AuthenticatedUser user) {
    final GenericAttribute<? extends Serializable> primary = user.getAttribute(user.getPrimaryAttribute());
    if (primary == null) {
      return null;
    }
    final List<Attribute> mapped = this.attributeMapping.toSaml(List.of(primary), null);
    return mapped.isEmpty() ? null : mapped.getFirst().getName();
  }

  /**
   * Gets the text of the sign message that was displayed for the user. A SAML sign message holds a single message, but
   * the result may come from an OpenID Connect request, so the language that was recorded picks the message.
   *
   * @param signMessage the sign message
   * @param language the language of the message that was displayed, may be {@code null}
   * @return the message text
   */
  private static @Nonnull String displayedText(final @Nonnull GenericSignMessage signMessage,
      final @Nullable String language) {
    final LocalizedMessage message = signMessage.getMessage(language);
    return message != null ? message.getText() : signMessage.getMessages().getFirst().getText();
  }

}
