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
package se.swedenconnect.spring.authnserver.authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

import java.time.Duration;
import java.util.List;

import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.SerializationTestSupport;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.message.GenericSignMessage;
import se.swedenconnect.spring.authnserver.message.GenericUserMessage;
import se.swedenconnect.spring.authnserver.message.LocalizedMessage;
import se.swedenconnect.spring.authnserver.message.MessageMimeType;

/**
 * Tests for {@link AuthenticationRequirements} and {@link OriginalRequester}.
 *
 * @author Martin Lindström
 */
class AuthenticationRequirementsTest {

  @SuppressWarnings("HttpUrlsUsage")
  static final String LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";

  @SuppressWarnings("HttpUrlsUsage")
  static final String LOA4 = "http://id.elegnamnden.se/loa/1.0/loa4";

  static AuthenticationRequirements requirements() {
    final AuthenticationRequirements requirements = new AuthenticationRequirements();
    requirements.setForceAuthn(true);
    requirements.setMaxAuthnAge(Duration.ofMinutes(30));
    requirements.setPassiveAuthn(false);
    requirements.setConsentRequired(true);
    requirements.setAuthnContextRequirements(List.of(LOA4, LOA3));
    requirements.setRequestedAttributes(List.of(
        GenericRequestedAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, true),
        GenericRequestedAttribute.of(AttributeIdentifiers.SURNAME)));
    requirements.setRequestedAuthnProviders(List.of("https://idp.example.com/idp"));
    requirements.setOriginalRequesters(List.of(new OriginalRequester("client-42", "dG9rZW4=")));
    requirements.setUserMessage(GenericUserMessage.ofText("sv", "Logga in hos Example"));
    requirements.setSignMessage(new GenericSignMessage(List.of(LocalizedMessage.ofText("sv", "Jag godkänner")),
        MessageMimeType.TEXT_MARKDOWN, true, "ZG9jLWhhc2g="));
    return requirements;
  }

  @Test
  void everythingDefaultsToNothingRequested() {
    final AuthenticationRequirements requirements = new AuthenticationRequirements();
    assertThat(requirements.isForceAuthn()).isFalse();
    assertThat(requirements.isPassiveAuthn()).isFalse();
    assertThat(requirements.isConsentRequired()).isFalse();
    assertThat(requirements.getMaxAuthnAge()).isNull();
    assertThat(requirements.getRequestedAttributes()).isEmpty();
    assertThat(requirements.getAuthnContextRequirements()).isEmpty();
    assertThat(requirements.getRequestedAuthnProviders()).isEmpty();
    assertThat(requirements.getOriginalRequesters()).isEmpty();
    assertThat(requirements.getSignMessage()).isNull();
    assertThat(requirements.getUserMessage()).isNull();
  }

  @Test
  void everyPropertyIsCarried() {
    final AuthenticationRequirements requirements = requirements();
    assertThat(requirements.isForceAuthn()).isTrue();
    assertThat(requirements.getMaxAuthnAge()).isEqualTo(Duration.ofMinutes(30));
    assertThat(requirements.isPassiveAuthn()).isFalse();
    assertThat(requirements.isConsentRequired()).isTrue();
    assertThat(requirements.getAuthnContextRequirements()).containsExactly(LOA4, LOA3);
    assertThat(requirements.getRequestedAttributes()).hasSize(2);
    assertThat(requirements.getRequestedAuthnProviders()).containsExactly("https://idp.example.com/idp");
    assertThat(requirements.getOriginalRequesters()).containsExactly(new OriginalRequester("client-42", "dG9rZW4="));
    assertThat(requirements.getUserMessage()).isNotNull();
    assertThat(requirements.getSignMessage()).isNotNull();
    assertThat(requirements.toString()).contains("force-authn=true", "consent-required=true", LOA4);
  }

  @Test
  void theAuthnContextOrderIsTheRequestersOrderOfPreference() {
    final AuthenticationRequirements requirements = new AuthenticationRequirements();
    requirements.setAuthnContextRequirements(List.of(LOA4, LOA3));
    assertThat(requirements.getAuthnContextRequirements()).containsExactly(LOA4, LOA3);
  }

  @Test
  void aMaximumAuthenticationAgeOfZeroMeansForceAuthentication() {
    final AuthenticationRequirements requirements = new AuthenticationRequirements();
    requirements.setMaxAuthnAge(Duration.ZERO);
    assertThat(requirements.isForceAuthn()).isTrue();

    requirements.setMaxAuthnAge(Duration.ofSeconds(1));
    assertThat(requirements.isForceAuthn()).isFalse();
  }

  @Test
  void aNegativeMaximumAuthenticationAgeIsRejected() {
    final AuthenticationRequirements requirements = new AuthenticationRequirements();
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> requirements.setMaxAuthnAge(Duration.ofSeconds(-1)))
        .withMessage("maxAuthnAge must not be negative");
  }

  @Test
  void theListsAreCopiedAndNullMeansEmpty() {
    final AuthenticationRequirements requirements = requirements();
    assertThatExceptionOfType(UnsupportedOperationException.class)
        .isThrownBy(() -> requirements.getAuthnContextRequirements().add(LOA3));

    requirements.setAuthnContextRequirements(null);
    requirements.setRequestedAttributes(null);
    requirements.setRequestedAuthnProviders(null);
    requirements.setOriginalRequesters(null);
    assertThat(requirements.getAuthnContextRequirements()).isEmpty();
    assertThat(requirements.getRequestedAttributes()).isEmpty();
    assertThat(requirements.getRequestedAuthnProviders()).isEmpty();
    assertThat(requirements.getOriginalRequesters()).isEmpty();
  }

  @Test
  @SuppressWarnings("DataFlowIssue")
  void anOriginalRequesterNeedsAnIdentifierButNoToken() {
    assertThat(OriginalRequester.of("client-42").token()).isNull();
    assertThatExceptionOfType(NullPointerException.class)
        .isThrownBy(() -> new OriginalRequester(null, null))
        .withMessage("identifier must not be null");
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new OriginalRequester(" ", null))
        .withMessage("identifier must not be empty");
  }

  @Test
  void equalRequirementsAreEqual() {
    assertThat(requirements()).isEqualTo(requirements()).hasSameHashCodeAs(requirements());

    final AuthenticationRequirements other = requirements();
    other.setConsentRequired(false);
    assertThat(other).isNotEqualTo(requirements());
    assertThat(requirements()).isNotEqualTo(null);
  }

  @Test
  void theRequirementsSurviveSerialization() throws Exception {
    final AuthenticationRequirements requirements = requirements();
    final AuthenticationRequirements restored = SerializationTestSupport.roundTrip(requirements);

    assertThat(restored).isEqualTo(requirements);
    assertThat(restored.getAuthnContextRequirements()).containsExactly(LOA4, LOA3);
    assertThat(restored.getRequestedAttributes()).isEqualTo(requirements.getRequestedAttributes());
    assertThat(restored.getOriginalRequesters()).containsExactly(new OriginalRequester("client-42", "dG9rZW4="));
    assertThat(restored.getUserMessage()).isNotNull()
        .satisfies(m -> assertThat(m.getMessage("sv")).isNotNull()
            .satisfies(sv -> assertThat(sv.getText()).isEqualTo("Logga in hos Example")));
    assertThat(restored.getSignMessage()).isNotNull()
        .satisfies(m -> {
          assertThat(m.isMustShow()).isTrue();
          assertThat(m.getTbsData()).isEqualTo("ZG9jLWhhc2g=");
        });
  }

  @Test
  void theResultCarriesTheRequirementsAndCanClearThem() throws Exception {
    final UserAuthentication authentication = new UserAuthentication(AuthenticatedUserTest.user());
    assertThat(authentication.getAuthnRequirements()).isNull();

    final AuthenticationRequirements requirements = requirements();
    authentication.setAuthnRequirements(requirements);
    assertThat(authentication.getAuthnRequirements()).isSameAs(requirements);

    final UserAuthentication restored = SerializationTestSupport.roundTrip(authentication);
    assertThat(restored.getAuthnRequirements()).isEqualTo(requirements);

    authentication.clearAuthnRequirements();
    assertThat(authentication.getAuthnRequirements()).isNull();
    assertThat(SerializationTestSupport.roundTrip(authentication).getAuthnRequirements()).isNull();
  }

}
