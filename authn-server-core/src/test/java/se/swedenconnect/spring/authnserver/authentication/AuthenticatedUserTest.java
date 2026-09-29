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

import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;

/**
 * Tests for {@link AuthenticatedUser}.
 *
 * @author Martin Lindström
 */
class AuthenticatedUserTest {

  static final String LOA3 = "http://id.elegnamnden.se/loa/1.0/loa3";

  static final Instant AUTHN_INSTANT = Instant.parse("2026-09-29T08:12:00Z");

  static AuthenticatedUser user() {
    return new AuthenticatedUser(
        List.of(
            GenericAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, "197705232382"),
            GenericAttribute.of(AttributeIdentifiers.GIVEN_NAME, "Agda"),
            GenericAttribute.of(AttributeIdentifiers.SURNAME, "Andersson")),
        AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, LOA3, AUTHN_INSTANT, "192.168.1.14");
  }

  @Test
  void theUserNameIsTheValueOfThePrimaryAttribute() {
    final AuthenticatedUser user = user();
    assertThat(user.getUsername()).isEqualTo("197705232382");
    assertThat(user.getPrimaryAttribute()).isEqualTo(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER);
    assertThat(user.getAuthnContextUri()).isEqualTo(LOA3);
    assertThat(user.getAuthnInstant()).isEqualTo(AUTHN_INSTANT);
    assertThat(user.getClientIpAddress()).isEqualTo("192.168.1.14");
    assertThat(user.getAttributes()).hasSize(3);
    assertThat(user.getAuthorities()).isEmpty();
    assertThat(user.getPassword()).isEmpty();
    assertThat(user.isEnabled()).isTrue();
    assertThat(user.isAccountNonExpired()).isTrue();
    assertThat(user.isAccountNonLocked()).isTrue();
    assertThat(user.isCredentialsNonExpired()).isTrue();
    assertThat(user.toString()).contains("197705232382", LOA3, "192.168.1.14");
  }

  @Test
  void attributesCanBeLookedUpByIdentifier() {
    final AuthenticatedUser user = user();
    assertThat(user.getAttribute(AttributeIdentifiers.GIVEN_NAME)).isNotNull()
        .satisfies(a -> assertThat(a.getValue()).isEqualTo("Agda"));
    assertThat(user.getAttribute(AttributeIdentifiers.EMAIL)).isNull();
  }

  @Test
  void theAttributeListIsUnmodifiable() {
    final AuthenticatedUser user = user();
    assertThatExceptionOfType(UnsupportedOperationException.class)
        .isThrownBy(() -> user.getAttributes().add(GenericAttribute.of(AttributeIdentifiers.EMAIL, "a@b.se")));
  }

  @Test
  void missingAttributesAreRejected() {
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new AuthenticatedUser(null, AttributeIdentifiers.SURNAME, LOA3, AUTHN_INSTANT, "127.0.0.1"))
        .withMessage("attributes must be set and not empty");
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(
            () -> new AuthenticatedUser(List.of(), AttributeIdentifiers.SURNAME, LOA3, AUTHN_INSTANT, "127.0.0.1"))
        .withMessage("attributes must be set and not empty");
  }

  @Test
  void aPrimaryAttributeThatIsNotAmongTheAttributesIsRejected() {
    final List<GenericAttribute<?>> attributes =
        List.of(GenericAttribute.of(AttributeIdentifiers.SURNAME, "Andersson"));
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new AuthenticatedUser(attributes, AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, LOA3,
            AUTHN_INSTANT, "127.0.0.1"))
        .withMessage("primaryAttribute must be set and appear among the attributes");
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new AuthenticatedUser(attributes, null, LOA3, AUTHN_INSTANT, "127.0.0.1"))
        .withMessage("primaryAttribute must be set and appear among the attributes");
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new AuthenticatedUser(attributes, "", LOA3, AUTHN_INSTANT, "127.0.0.1"))
        .withMessage("primaryAttribute must be set and appear among the attributes");
  }

  @Test
  void missingAuthnContextInstantOrClientIpAddressIsRejected() {
    final List<GenericAttribute<?>> attributes =
        List.of(GenericAttribute.of(AttributeIdentifiers.SURNAME, "Andersson"));
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new AuthenticatedUser(attributes, AttributeIdentifiers.SURNAME, null, AUTHN_INSTANT,
            "127.0.0.1"))
        .withMessage("authnContextUri must be set and not empty");
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new AuthenticatedUser(attributes, AttributeIdentifiers.SURNAME, " ", AUTHN_INSTANT,
            "127.0.0.1"))
        .withMessage("authnContextUri must be set and not empty");
    assertThatExceptionOfType(NullPointerException.class)
        .isThrownBy(() -> new AuthenticatedUser(attributes, AttributeIdentifiers.SURNAME, LOA3, null, "127.0.0.1"))
        .withMessage("authnInstant must not be null");
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new AuthenticatedUser(attributes, AttributeIdentifiers.SURNAME, LOA3, AUTHN_INSTANT, null))
        .withMessage("clientIpAddress must be set and not empty");
    assertThatExceptionOfType(IllegalArgumentException.class)
        .isThrownBy(() -> new AuthenticatedUser(attributes, AttributeIdentifiers.SURNAME, LOA3, AUTHN_INSTANT, ""))
        .withMessage("clientIpAddress must be set and not empty");
  }

  @Test
  void theSignMessageLanguageIsRecordedOnlyWhenAMessageWasDisplayed() {
    final AuthenticatedUser user = user();
    assertThat(user.isSignMessageDisplayed()).isFalse();
    assertThat(user.getSignMessageLanguage()).isNull();

    user.setSignMessageDisplayed(true, "sv");
    assertThat(user.isSignMessageDisplayed()).isTrue();
    assertThat(user.getSignMessageLanguage()).isEqualTo("sv");
    assertThat(user.toString()).contains("sign-message-displayed=true", "sign-message-language=sv");

    user.setSignMessageDisplayed(false, "sv");
    assertThat(user.isSignMessageDisplayed()).isFalse();
    assertThat(user.getSignMessageLanguage()).isNull();
  }

  @Test
  void equalObjectsAreEqual() {
    assertThat(user()).isEqualTo(user()).hasSameHashCodeAs(user());
    assertThat(user()).isNotEqualTo(null).isNotEqualTo("197705232382");

    final AuthenticatedUser other = user();
    other.setSignMessageDisplayed(true, "sv");
    assertThat(other).isNotEqualTo(user());
  }

  @Test
  void theUserSurvivesSerialization() throws Exception {
    final AuthenticatedUser user = user();
    user.setSignMessageDisplayed(true, "en");

    final AuthenticatedUser restored = SerializationTestSupport.roundTrip(user);
    assertThat(restored).isEqualTo(user);
    assertThat(restored.getUsername()).isEqualTo("197705232382");
    assertThat(restored.getAttributes()).isEqualTo(user.getAttributes());
    assertThat(restored.isSignMessageDisplayed()).isTrue();
    assertThat(restored.getSignMessageLanguage()).isEqualTo("en");
  }

}
