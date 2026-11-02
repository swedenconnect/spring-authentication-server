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
package se.swedenconnect.spring.authnserver.oidc.scope;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;

import org.assertj.core.api.InstanceOfAssertFactories;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;

import se.oidc.nimbus.claims.ClaimConstants;
import se.oidc.nimbus.claims.OidcScopeValue;
import se.oidc.nimbus.claims.ScopeConstants;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.oidc.attributes.OidcAttributeMapping;

/**
 * Tests for {@link SupportedScopesAndClaims}.
 *
 * @author Martin Lindström
 */
class SupportedScopesAndClaimsTest {

  private static final String OPENID = OidcScopeValue.OPENID.getValue();

  private static final String PROFILE = OidcScopeValue.PROFILE.getValue();

  private static final String NATURAL_PERSON_INFO = ScopeConstants.NATURAL_PERSON_INFO.getValue();

  private static final String NATURAL_PERSON_NUMBER = ScopeConstants.NATURAL_PERSON_PERSONAL_NUMBER.getValue();

  private static final String SIGN = ScopeConstants.SIGN.getValue();

  private static final String SIGN_APPROVAL = ScopeConstants.SIGN_APPROVAL.getValue();

  private static final String PHONE = OidcScopeValue.PHONE.getValue();

  /** Delivers the user signature, declares no scopes. */
  private static final TestAuthenticationProvider SIGNER = new TestAuthenticationProvider("signer", List.of(),
      List.of(AttributeIdentifiers.USER_SIGNATURE), List.of());

  /** Delivers a personal identity number and names, declares no scopes. */
  private static final TestAuthenticationProvider PERSON = new TestAuthenticationProvider("person", List.of(),
      List.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, AttributeIdentifiers.GIVEN_NAME,
          AttributeIdentifiers.SURNAME, AttributeIdentifiers.DISPLAY_NAME, AttributeIdentifiers.DATE_OF_BIRTH),
      List.of());

  private final OidcAttributeMapping mapping = new OidcAttributeMapping();

  private final ScopeRegistry registry = new DefaultScopeRegistry();

  private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

  @BeforeEach
  void addAppender() {
    this.appender.start();
    ((Logger) LoggerFactory.getLogger(SupportedScopesAndClaims.class)).addAppender(this.appender);
  }

  @AfterEach
  void removeAppender() {
    ((Logger) LoggerFactory.getLogger(SupportedScopesAndClaims.class)).detachAppender(this.appender);
  }

  @Test
  void aScopeIsDerivedWhenAllItsEssentialClaimsAreDelivered() {
    final SupportedScopesAndClaims result = this.resolve(List.of(PERSON), null, null);

    assertThat(result.scopes()).containsExactlyInAnyOrder(OPENID, PROFILE, NATURAL_PERSON_INFO);
    assertThat(result.scopes()).doesNotContain(NATURAL_PERSON_NUMBER, OidcScopeValue.EMAIL.getValue(), SIGN,
        SIGN_APPROVAL);
    assertThat(result.scopes().getFirst()).isEqualTo(OPENID);
    assertThat(this.warnings()).isEmpty();
  }

  @Test
  void aConfiguredClaimCountsWhenScopesAreDerived() {
    final SupportedScopesAndClaims result =
        this.resolve(List.of(PERSON), null, List.of(ClaimConstants.COORDINATION_NUMBER_CLAIM_NAME));

    assertThat(result.scopes()).contains(NATURAL_PERSON_NUMBER);
    assertThat(result.claims()).contains(ClaimConstants.COORDINATION_NUMBER_CLAIM_NAME);
  }

  @Test
  void theSignScopesAreNeverDerived() {
    final SupportedScopesAndClaims result =
        this.resolve(List.of(SIGNER), null, List.of(ClaimConstants.USER_SIGNATURE_CLAIM_NAME));

    assertThat(result.scopes()).containsExactly(OPENID);
    assertThat(result.claims()).contains(ClaimConstants.USER_SIGNATURE_CLAIM_NAME, "auth_time");
    assertThat(this.warnings()).isEmpty();
  }

  @Test
  void aDeclaredSignScopeIsOfferedWithoutWarningWhenTheUserSignatureIsSupported() {
    final TestAuthenticationProvider signer = new TestAuthenticationProvider("signer", List.of(),
        List.of(AttributeIdentifiers.USER_SIGNATURE), List.of(SIGN, SIGN_APPROVAL));

    assertThat(this.resolve(List.of(signer), null, null).scopes()).containsExactly(OPENID, SIGN, SIGN_APPROVAL);
    assertThat(this.warnings()).isEmpty();
  }

  @Test
  void aDeclaredSignScopeWithoutTheUserSignatureIsOfferedWithAWarning() {
    final TestAuthenticationProvider declaring = new TestAuthenticationProvider("declaring", List.of(),
        List.of(AttributeIdentifiers.GIVEN_NAME), List.of(SIGN));

    assertThat(this.resolve(List.of(declaring), null, null).scopes()).containsExactly(OPENID, SIGN);
    assertThat(this.warnings()).singleElement(InstanceOfAssertFactories.STRING)
        .contains(SIGN, ClaimConstants.USER_SIGNATURE_CLAIM_NAME);
  }

  @Test
  void aConfiguredSignScopeWithoutTheUserSignatureIsOfferedWithAWarning() {
    assertThat(this.resolve(List.of(PERSON), List.of(SIGN), null).scopes()).containsExactly(OPENID, SIGN);
    assertThat(this.warnings()).singleElement(InstanceOfAssertFactories.STRING)
        .contains(SIGN, ClaimConstants.USER_SIGNATURE_CLAIM_NAME);
  }

  @Test
  void aScopeWithNoneOfItsClaimsSupportedIsOfferedWithAWarning() {
    final TestAuthenticationProvider declaring = new TestAuthenticationProvider("declaring", List.of(),
        List.of(AttributeIdentifiers.GIVEN_NAME), List.of(PHONE));

    assertThat(this.resolve(List.of(declaring), null, null).scopes()).containsExactly(OPENID, PHONE);
    assertThat(this.resolve(List.of(PERSON), List.of(PHONE), null).scopes()).containsExactly(OPENID, PHONE);
    assertThat(this.warnings()).hasSize(2).allMatch(m -> m.contains(PHONE) && m.contains("phone_number"));
  }

  @Test
  void aScopeWithSomeOfItsClaimsSupportedOrWithoutClaimsGetsNoWarning() {
    final SupportedScopesAndClaims result =
        this.resolve(List.of(PERSON), List.of(PROFILE, NATURAL_PERSON_NUMBER, SIGN_APPROVAL), null);

    assertThat(result.scopes()).containsExactly(OPENID, PROFILE, NATURAL_PERSON_NUMBER, SIGN_APPROVAL);
    assertThat(result.claims()).doesNotContain("zoneinfo", ClaimConstants.COORDINATION_NUMBER_CLAIM_NAME);
    assertThat(this.warnings()).isEmpty();
  }

  @Test
  void aProviderThatDeclaresScopesOffersExactlyThose() {
    final TestAuthenticationProvider declaring = new TestAuthenticationProvider("declaring", List.of(),
        List.of(AttributeIdentifiers.GIVEN_NAME), List.of(SIGN_APPROVAL));

    final SupportedScopesAndClaims result = this.resolve(List.of(declaring), null, null);

    assertThat(result.scopes()).containsExactly(OPENID, SIGN_APPROVAL);
    assertThat(result.claims()).containsExactly("sub", "auth_time", "acr", "given_name");
  }

  @Test
  void theOfferedScopesAreTheUnionOverTheProviders() {
    final TestAuthenticationProvider email = new TestAuthenticationProvider("email", List.of(),
        List.of(AttributeIdentifiers.EMAIL), List.of());

    assertThat(this.resolve(List.of(PERSON, email), null, null).scopes())
        .containsExactlyInAnyOrder(OPENID, PROFILE, NATURAL_PERSON_INFO, OidcScopeValue.EMAIL.getValue());
  }

  @Test
  void configuredScopesReplaceTheDerivedOnesAndOpenidIsAlwaysOffered() {
    final SupportedScopesAndClaims result =
        this.resolve(List.of(PERSON), List.of(OidcScopeValue.PHONE.getValue()), null);

    assertThat(result.scopes()).containsExactly(OPENID, OidcScopeValue.PHONE.getValue());
    assertThat(result.claims()).contains("given_name", ClaimConstants.PERSONAL_IDENTITY_NUMBER_CLAIM_NAME, "sub");
    assertThat(result.claims()).doesNotContain("phone_number", "phone_number_verified", "zoneinfo");
  }

  @Test
  void theClaimsAreOnlyThoseThatAreDeliveredOrConfigured() {
    final SupportedScopesAndClaims result = this.resolve(List.of(PERSON), null, List.of("custom_claim"));

    assertThat(result.scopes()).contains(PROFILE);
    assertThat(result.claims()).containsExactlyInAnyOrder("sub", "auth_time", "acr", "custom_claim",
        ClaimConstants.PERSONAL_IDENTITY_NUMBER_CLAIM_NAME, "given_name", "family_name", "name", "birthdate");
    assertThat(result.claims()).doesNotContain("zoneinfo", "website", "nickname", "updated_at");
  }

  @Test
  void aConfiguredClaimOfAnOfferedScopeIsSupported() {
    final SupportedScopesAndClaims result = this.resolve(List.of(PERSON), null, List.of("zoneinfo"));

    assertThat(result.claims()).contains("zoneinfo");
    assertThat(result.claims()).doesNotContain("website");
  }

  @Test
  void anUnknownScopeIsRejected() {
    final TestAuthenticationProvider unknown =
        new TestAuthenticationProvider("unknown", List.of(), List.of(), List.of("https://example.com/unknown"));

    assertThatThrownBy(() -> this.resolve(List.of(unknown), null, null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("https://example.com/unknown")
        .hasMessageContaining("unknown");
    assertThatThrownBy(() -> this.resolve(List.of(), List.of("nope"), null))
        .isInstanceOf(IllegalArgumentException.class)
        .hasMessageContaining("nope");
  }

  @Test
  void withoutProvidersOnlyOpenidIsOffered() {
    final SupportedScopesAndClaims result = this.resolve(List.of(), null, null);

    assertThat(result.scopes()).containsExactly(OPENID);
    assertThat(result.claims()).containsExactly("sub", "auth_time", "acr");
  }

  @Test
  void theOtherIdTokenClaimsAreNotPublished() {
    assertThat(this.resolve(List.of(PERSON), null, null).claims())
        .doesNotContain("iss", "aud", "exp", "iat", "nonce");
  }

  private List<String> warnings() {
    return this.appender.list.stream()
        .filter(e -> e.getLevel() == Level.WARN)
        .map(ILoggingEvent::getFormattedMessage)
        .toList();
  }

  private SupportedScopesAndClaims resolve(final List<TestAuthenticationProvider> providers,
      final List<String> scopes, final List<String> claims) {
    return SupportedScopesAndClaims.resolve(providers, this.mapping, this.registry, scopes, claims);
  }

}
