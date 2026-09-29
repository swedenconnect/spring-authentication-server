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
package se.swedenconnect.spring.authnserver.saml.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.OriginalRequester;
import se.swedenconnect.spring.authnserver.message.GenericSignMessage;

/**
 * Tests for {@link SamlAuthenticationRequirements} and {@link SadRequestExtension}.
 *
 * @author Martin Lindström
 */
class SamlAuthenticationRequirementsTest {

  @SuppressWarnings("HttpUrlsUsage")
  static final String LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";

  @SuppressWarnings("HttpUrlsUsage")
  static final String SIGN_CATEGORY = "http://id.elegnamnden.se/st/1.0/sigservice";

  static SamlAuthenticationRequirements requirements() {
    final SamlAuthenticationRequirements requirements = new SamlAuthenticationRequirements();
    requirements.setForceAuthn(true);
    requirements.setAuthnContextRequirements(List.of(LOA3));
    requirements.setOriginalRequesters(List.of(OriginalRequester.of("https://sp.example.com/sp")));
    requirements.setSignMessage(GenericSignMessage.ofText(null, "Jag godkänner"));
    requirements.setEntityCategories(List.of(SIGN_CATEGORY));
    requirements.setSadRequestExtension(new SadRequestExtension("_sad1", "https://sp.example.com/sp", "_sign1", 3));
    return requirements;
  }

  @Test
  void theSamlSubtypeAddsEntityCategoriesAndTheSadRequest() {
    final SamlAuthenticationRequirements requirements = requirements();
    assertThat(requirements).isInstanceOf(AuthenticationRequirements.class);
    assertThat(requirements.getEntityCategories()).containsExactly(SIGN_CATEGORY);
    assertThat(requirements.getSadRequestExtension()).isNotNull();
    assertThat(requirements.getSadRequestExtension().getId()).isEqualTo("_sad1");
    assertThat(requirements.getSadRequestExtension().getRequesterId()).isEqualTo("https://sp.example.com/sp");
    assertThat(requirements.getSadRequestExtension().getSignRequestId()).isEqualTo("_sign1");
    assertThat(requirements.getSadRequestExtension().getDocumentCount()).isEqualTo(3);
    assertThat(requirements.toString()).contains("entity-categories", "sad-request", LOA3);
  }

  @Test
  void anEmptySamlSubtypeHasNoSamlAdditions() {
    final SamlAuthenticationRequirements requirements = new SamlAuthenticationRequirements();
    assertThat(requirements.getEntityCategories()).isEmpty();
    assertThat(requirements.getSadRequestExtension()).isNull();

    requirements.setEntityCategories(null);
    assertThat(requirements.getEntityCategories()).isEmpty();
    assertThatExceptionOfType(UnsupportedOperationException.class)
        .isThrownBy(() -> requirements().getEntityCategories().add("x"));
  }

  @Test
  void theSamlSubtypeCanBeBuiltFromGenericRequirements() {
    final AuthenticationRequirements generic = new AuthenticationRequirements();
    generic.setPassiveAuthn(true);
    generic.setMaxAuthnAge(Duration.ofMinutes(10));
    generic.setAuthnContextRequirements(List.of(LOA3));

    final SamlAuthenticationRequirements requirements = new SamlAuthenticationRequirements(generic);
    assertThat(requirements.isPassiveAuthn()).isTrue();
    assertThat(requirements.getMaxAuthnAge()).isEqualTo(Duration.ofMinutes(10));
    assertThat(requirements.getAuthnContextRequirements()).containsExactly(LOA3);
    assertThat(requirements.getEntityCategories()).isEmpty();
  }

  @Test
  void theSamlSubtypeIsNeverEqualToTheGenericRequirements() {
    final SamlAuthenticationRequirements requirements = requirements();
    assertThat(requirements).isEqualTo(requirements()).hasSameHashCodeAs(requirements());
    assertThat(requirements).isNotEqualTo(new AuthenticationRequirements());

    final SamlAuthenticationRequirements other = requirements();
    other.setEntityCategories(List.of());
    assertThat(other).isNotEqualTo(requirements);
  }

  @Test
  void aSadRequestExtensionMayBeEmpty() {
    final SadRequestExtension extension = new SadRequestExtension(null, null, null, null);
    assertThat(extension.getId()).isNull();
    assertThat(extension.getRequesterId()).isNull();
    assertThat(extension.getSignRequestId()).isNull();
    assertThat(extension.getDocumentCount()).isNull();
    assertThat(extension).isEqualTo(new SadRequestExtension(null, null, null, null))
        .isNotEqualTo(new SadRequestExtension("_sad1", null, null, null));
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void aMissingSadRequestIsRejected() {
    assertThatExceptionOfType(NullPointerException.class)
        .isThrownBy(() -> new SadRequestExtension(null))
        .withMessage("sadRequest must not be null");
  }

  @Test
  void theSamlSubtypeSurvivesSerialization() throws Exception {
    final SamlAuthenticationRequirements requirements = requirements();
    final SamlAuthenticationRequirements restored = roundTrip(requirements);

    assertThat(restored).isEqualTo(requirements);
    assertThat(restored.isForceAuthn()).isTrue();
    assertThat(restored.getAuthnContextRequirements()).containsExactly(LOA3);
    assertThat(restored.getEntityCategories()).containsExactly(SIGN_CATEGORY);
    assertThat(restored.getSadRequestExtension()).isEqualTo(requirements.getSadRequestExtension());
    assertThat(restored.getSignMessage()).isNotNull()
        .satisfies(m -> assertThat(m.getDefaultMessage()).isNotNull()
            .satisfies(text -> assertThat(text.getText()).isEqualTo("Jag godkänner")));
  }

  @SuppressWarnings("unchecked")
  private static <T extends Serializable> T roundTrip(final T object) throws Exception {
    final ByteArrayOutputStream bytes = new ByteArrayOutputStream();
    try (final ObjectOutputStream out = new ObjectOutputStream(bytes)) {
      out.writeObject(object);
    }
    try (final ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes.toByteArray()))) {
      return (T) in.readObject();
    }
  }

}
