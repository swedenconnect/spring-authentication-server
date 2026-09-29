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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import org.junit.jupiter.api.Test;
import org.mockito.Answers;
import org.mockito.Mockito;
import org.opensaml.saml.saml2.core.Attribute;

import se.swedenconnect.opensaml.sweid.saml2.attribute.AttributeConstants;
import se.swedenconnect.opensaml.sweid.saml2.signservice.SADFactory;
import se.swedenconnect.opensaml.sweid.saml2.signservice.SADFactory.SADBuilder;
import se.swedenconnect.opensaml.sweid.saml2.signservice.SignMessageDigestIssuer;
import se.swedenconnect.opensaml.sweid.saml2.signservice.dss.Message;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;
import se.swedenconnect.spring.authnserver.error.AuthenticationError;
import se.swedenconnect.spring.authnserver.error.AuthenticationErrorException;
import se.swedenconnect.spring.authnserver.message.GenericSignMessage;
import se.swedenconnect.spring.authnserver.saml.attributes.OpenSamlTestBase;
import se.swedenconnect.spring.authnserver.saml.attributes.SamlAttributeMapping;
import se.swedenconnect.spring.authnserver.saml.authentication.SadRequestExtension;
import se.swedenconnect.spring.authnserver.saml.authentication.SamlAuthenticationRequirements;

/**
 * Tests for {@link SwedenConnectAttributeProducer}.
 *
 * @author Martin Lindström
 */
class SwedenConnectAttributeProducerTest extends OpenSamlTestBase {

  private static final String SIGN_MESSAGE_TEXT = "I hereby confirm that I want to join example.com as a customer";

  private final SwedenConnectAttributeProducer producer = new SwedenConnectAttributeProducer();

  private static UserAuthentication authentication(final SamlAuthenticationRequirements requirements,
      final boolean signMessageDisplayed) {
    final AuthenticatedUser user = new AuthenticatedUser(
        List.of(GenericAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, "197705232382"),
            GenericAttribute.of(AttributeIdentifiers.SURNAME, "Andersson")),
        AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, "http://id.elegnamnden.se/loa/1.0/loa3", Instant.now(),
        "192.168.1.14");
    if (signMessageDisplayed) {
      user.setSignMessageDisplayed(true, null);
    }
    final UserAuthentication authentication = new UserAuthentication(user);
    authentication.registerUse(AuthenticationProtocol.SAML, "https://sp.example.com/sp", "_1", List.of());
    authentication.setAuthnRequirements(requirements);
    return authentication;
  }

  private static SamlAuthenticationRequirements requirements(final boolean withSignMessage, final boolean mustShow) {
    final SamlAuthenticationRequirements requirements = new SamlAuthenticationRequirements();
    requirements.setRequestedAttributes(
        List.of(GenericRequestedAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER)));
    if (withSignMessage) {
      requirements.setSignMessage(new GenericSignMessage(
          List.of(se.swedenconnect.spring.authnserver.message.LocalizedMessage.ofText(null, SIGN_MESSAGE_TEXT)),
          null, mustShow, null));
    }
    return requirements;
  }

  private static String value(final List<GenericAttribute<? extends Serializable>> attributes,
      final String identifier) {
    return attributes.stream()
        .filter(a -> a.getIdentifier().equals(identifier))
        .map(a -> String.valueOf(a.getValue()))
        .findFirst()
        .orElse(null);
  }

  private static List<String> identifiers(final List<GenericAttribute<? extends Serializable>> attributes) {
    return attributes.stream().map(GenericAttribute::getIdentifier).toList();
  }

  private static SADFactory sadFactory(final String jwt) throws Exception {
    final SADBuilder builder = Mockito.mock(SADBuilder.class, Answers.RETURNS_SELF);
    Mockito.when(builder.buildJwt()).thenReturn(jwt);
    final SADFactory factory = Mockito.mock(SADFactory.class);
    Mockito.when(factory.getBuilder(Mockito.anyString())).thenReturn(builder);
    Mockito.when(factory.getBuilder()).thenReturn(builder);
    return factory;
  }

  private static SadRequestExtension sadRequest() {
    return new SadRequestExtension("_sad-request", "https://sp.example.com/sp", "_sign-request", 2);
  }

  // ---- The requested attributes ----

  @Test
  void theRequestedAttributesAreReleased() {
    final List<GenericAttribute<? extends Serializable>> released =
        this.producer.releaseAttributes(authentication(requirements(false, false), false));

    assertThat(identifiers(released)).containsExactly(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER);
  }

  // ---- The sign message digest ----

  @Test
  void theSignMessageDigestIsReleasedWhenTheMessageWasDisplayed() throws Exception {
    final List<GenericAttribute<? extends Serializable>> released =
        this.producer.releaseAttributes(authentication(requirements(true, true), true));

    final String expected = SignMessageDigestIssuer.DEFAULT_DIGEST_METHOD + ";"
        + Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256")
            .digest(SIGN_MESSAGE_TEXT.getBytes(StandardCharsets.UTF_8)));

    assertThat(identifiers(released)).containsExactly(
        AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, AttributeIdentifiers.SIGN_MESSAGE_DIGEST);
    assertThat(value(released, AttributeIdentifiers.SIGN_MESSAGE_DIGEST)).isEqualTo(expected);
  }

  @Test
  void noSignMessageDigestWhenTheRequestCarriedNoSignMessage() {
    final List<GenericAttribute<? extends Serializable>> released =
        this.producer.releaseAttributes(authentication(requirements(false, false), true));

    assertThat(identifiers(released)).doesNotContain(AttributeIdentifiers.SIGN_MESSAGE_DIGEST);
  }

  @Test
  void noSignMessageDigestWhenTheMessageWasNotDisplayed() {
    final List<GenericAttribute<? extends Serializable>> released =
        this.producer.releaseAttributes(authentication(requirements(true, true), false));

    assertThat(identifiers(released)).doesNotContain(AttributeIdentifiers.SIGN_MESSAGE_DIGEST);
  }

  @Test
  void aFailingDigestForAMessageThatMustBeShownIsAnError() {
    this.producer.setSignMessageDigestIssuer(failingDigestIssuer());

    assertThatExceptionOfType(AuthenticationErrorException.class)
        .isThrownBy(() -> this.producer.releaseAttributes(authentication(requirements(true, true), true)))
        .satisfies(e -> assertThat(e.getError()).isEqualTo(AuthenticationError.SIGN_MESSAGE_NOT_DISPLAYED));
  }

  @Test
  void aFailingDigestForAMessageThatNeedNotBeShownLeavesTheDigestOut() {
    this.producer.setSignMessageDigestIssuer(failingDigestIssuer());

    final List<GenericAttribute<? extends Serializable>> released =
        this.producer.releaseAttributes(authentication(requirements(true, false), true));

    assertThat(identifiers(released)).containsExactly(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER);
  }

  // ---- The SAD ----

  @Test
  void theSadIsReleasedTogetherWithTheSignMessageDigest() throws Exception {
    final SamlAuthenticationRequirements requirements = requirements(true, true);
    requirements.setSadRequestExtension(sadRequest());
    this.producer.setSadFactory(sadFactory("the-sad-jwt"));

    final List<GenericAttribute<? extends Serializable>> released =
        this.producer.releaseAttributes(authentication(requirements, true));

    assertThat(identifiers(released)).containsExactly(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER,
        AttributeIdentifiers.SIGN_MESSAGE_DIGEST, AttributeIdentifiers.SAD);
    assertThat(value(released, AttributeIdentifiers.SAD)).isEqualTo("the-sad-jwt");
  }

  @Test
  void theSadRecordsTheSamlNameOfThePrimaryAttribute() throws Exception {
    final SamlAuthenticationRequirements requirements = requirements(true, true);
    requirements.setSadRequestExtension(sadRequest());
    final SADFactory factory = sadFactory("the-sad-jwt");
    this.producer.setSadFactory(factory);

    this.producer.releaseAttributes(authentication(requirements, true));

    Mockito.verify(factory).getBuilder(AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER);
  }

  @Test
  void noSadWithoutASignMessageDigest() throws Exception {
    final SamlAuthenticationRequirements requirements = requirements(false, false);
    requirements.setSadRequestExtension(sadRequest());
    this.producer.setSadFactory(sadFactory("the-sad-jwt"));

    assertThat(identifiers(this.producer.releaseAttributes(authentication(requirements, true))))
        .doesNotContain(AttributeIdentifiers.SAD);
  }

  @Test
  void noSadWithoutASadRequest() throws Exception {
    this.producer.setSadFactory(sadFactory("the-sad-jwt"));

    assertThat(identifiers(this.producer.releaseAttributes(authentication(requirements(true, true), true))))
        .doesNotContain(AttributeIdentifiers.SAD);
  }

  @Test
  void noSadWithoutASadFactory() {
    final SamlAuthenticationRequirements requirements = requirements(true, true);
    requirements.setSadRequestExtension(sadRequest());

    assertThat(this.producer.getSadFactory()).isNull();
    assertThat(identifiers(this.producer.releaseAttributes(authentication(requirements, true))))
        .doesNotContain(AttributeIdentifiers.SAD);
  }

  @Test
  void aFailingSadLeavesTheSadOut() throws Exception {
    final SamlAuthenticationRequirements requirements = requirements(true, true);
    requirements.setSadRequestExtension(sadRequest());

    final SADBuilder builder = Mockito.mock(SADBuilder.class, Answers.RETURNS_SELF);
    Mockito.when(builder.buildJwt()).thenThrow(new java.security.SignatureException("no key"));
    final SADFactory factory = Mockito.mock(SADFactory.class);
    Mockito.when(factory.getBuilder(Mockito.anyString())).thenReturn(builder);
    this.producer.setSadFactory(factory);

    assertThat(identifiers(this.producer.releaseAttributes(authentication(requirements, true))))
        .doesNotContain(AttributeIdentifiers.SAD);
  }

  // ---- Mapping the released attributes ----

  @Test
  void theReleasedAttributesMapToSamlAttributes() throws Exception {
    final SamlAuthenticationRequirements requirements = requirements(true, true);
    requirements.setSadRequestExtension(sadRequest());
    this.producer.setSadFactory(sadFactory("the-sad-jwt"));

    final List<Attribute> attributes = new SamlAttributeMapping().toSaml(
        this.producer.releaseAttributes(authentication(requirements, true)),
        requirements.getRequestedAttributes());

    assertThat(attributes).extracting(Attribute::getName).containsExactlyInAnyOrder(
        AttributeConstants.ATTRIBUTE_NAME_PERSONAL_IDENTITY_NUMBER,
        AttributeConstants.ATTRIBUTE_NAME_SIGNMESSAGE_DIGEST,
        AttributeConstants.ATTRIBUTE_NAME_SAD);
  }

  /**
   * Creates a digest issuer that fails.
   *
   * @return a {@link SignMessageDigestIssuer}
   */
  private static SignMessageDigestIssuer failingDigestIssuer() {
    final SignMessageDigestIssuer issuer = Mockito.mock(SignMessageDigestIssuer.class);
    Mockito.when(issuer.create(Mockito.any(Message.class)))
        .thenThrow(new IllegalArgumentException("The digest algorithm is not supported"));
    return issuer;
  }

}
