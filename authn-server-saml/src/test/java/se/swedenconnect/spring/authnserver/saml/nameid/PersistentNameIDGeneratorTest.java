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
package se.swedenconnect.spring.authnserver.saml.nameid;

import static org.assertj.core.api.Assertions.assertThat;
import static se.swedenconnect.spring.authnserver.saml.nameid.NameIDTestSupport.IDENTITY_NUMBER;
import static se.swedenconnect.spring.authnserver.saml.nameid.NameIDTestSupport.IDP;
import static se.swedenconnect.spring.authnserver.saml.nameid.NameIDTestSupport.SECRET;
import static se.swedenconnect.spring.authnserver.saml.nameid.NameIDTestSupport.SP;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.NameID;

import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.saml.attributes.OpenSamlTestBase;

/**
 * Tests for {@link PersistentNameIDGenerator}.
 *
 * @author Martin Lindström
 */
class PersistentNameIDGeneratorTest extends OpenSamlTestBase {

  private static final AuthenticatedUser USER = NameIDTestSupport.user();

  private static final Requester REQUESTER = NameIDTestSupport.requester(SP);

  private static PersistentNameIDGenerator generator(final String spNameQualifier, final byte[] secret) {
    final PersistentNameIDGenerator generator = new PersistentNameIDGenerator(IDP, spNameQualifier);
    generator.setSecret(secret);
    return generator;
  }

  @Test
  void theNameIDIsBuilt() {
    final NameID nameID = generator(SP, null).getNameID(USER, REQUESTER);
    assertThat(nameID.getFormat()).isEqualTo(NameID.PERSISTENT);
    assertThat(nameID.getNameQualifier()).isEqualTo(IDP);
    assertThat(nameID.getSPNameQualifier()).isEqualTo(SP);
    assertThat(nameID.getValue()).isNotEmpty().doesNotContain(IDENTITY_NUMBER);
  }

  @Test
  void withoutASpNameQualifierNoneIsAssigned() {
    final NameID nameID = generator(null, null).getNameID(USER, REQUESTER);
    assertThat(nameID.getNameQualifier()).isEqualTo(IDP);
    assertThat(nameID.getSPNameQualifier()).isNull();
  }

  @Test
  void withoutASecretTheValueIsTheSameAsInSamlIdentityProvider() throws Exception {
    assertThat(generator(SP, null).getSubjectIdentifier(USER, REQUESTER))
        .isEqualTo(NameIDTestSupport.samlIdentityProviderValue(SP, IDP, IDENTITY_NUMBER));
  }

  @Test
  void withoutASpNameQualifierTheValueIsTheSameAsInSamlIdentityProvider() throws Exception {
    assertThat(generator(null, null).getSubjectIdentifier(USER, REQUESTER))
        .isEqualTo(NameIDTestSupport.samlIdentityProviderValue(null, IDP, IDENTITY_NUMBER));
  }

  @Test
  void theValueIsStable() {
    assertThat(generator(SP, null).getSubjectIdentifier(USER, REQUESTER))
        .isEqualTo(generator(SP, null).getSubjectIdentifier(NameIDTestSupport.user(), REQUESTER));
  }

  @Test
  void theValueDiffersBetweenServiceProviders() {
    assertThat(generator(SP, null).getSubjectIdentifier(USER, REQUESTER))
        .isNotEqualTo(generator("https://other-sp.example.com", null).getSubjectIdentifier(USER, REQUESTER));
  }

  @Test
  void theValueDiffersBetweenUsers() {
    assertThat(generator(SP, null).getSubjectIdentifier(USER, REQUESTER))
        .isNotEqualTo(generator(SP, null).getSubjectIdentifier(NameIDTestSupport.user("198906121234"), REQUESTER));
  }

  @Test
  void withASecretTheValueDiffersButIsStable() throws Exception {
    final String withSecret = generator(SP, SECRET).getSubjectIdentifier(USER, REQUESTER);
    assertThat(withSecret)
        .isNotEqualTo(NameIDTestSupport.samlIdentityProviderValue(SP, IDP, IDENTITY_NUMBER))
        .isEqualTo(generator(SP, SECRET).getSubjectIdentifier(USER, REQUESTER))
        .doesNotContain(IDENTITY_NUMBER);
  }

  @Test
  void twoSecretsGiveTwoValues() {
    assertThat(generator(SP, SECRET).getSubjectIdentifier(USER, REQUESTER))
        .isNotEqualTo(generator(SP, "another-secret".getBytes(StandardCharsets.UTF_8))
            .getSubjectIdentifier(USER, REQUESTER));
  }

  @Test
  void theGeneratorSurvivesSerialization() throws Exception {
    final PersistentNameIDGenerator generator = generator(SP, SECRET);
    final String expected = generator.getSubjectIdentifier(USER, REQUESTER);
    final PersistentNameIDGenerator restored = NameIDTestSupport.roundTrip(generator);
    assertThat(restored.getSubjectIdentifier(USER, REQUESTER)).isEqualTo(expected);
    assertThat(restored.getNameID(USER, REQUESTER).getSPNameQualifier()).isEqualTo(SP);
  }

}
