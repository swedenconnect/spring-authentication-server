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
import static se.swedenconnect.spring.authnserver.saml.nameid.NameIDTestSupport.SP;

import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.core.NameID;

import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.Requester;
import se.swedenconnect.spring.authnserver.saml.attributes.OpenSamlTestBase;

/**
 * Tests for {@link TransientNameIDGenerator}.
 *
 * @author Martin Lindström
 */
class TransientNameIDGeneratorTest extends OpenSamlTestBase {

  private static final AuthenticatedUser USER = NameIDTestSupport.user();

  private static final Requester REQUESTER = NameIDTestSupport.requester(SP);

  @Test
  void theNameIDIsBuilt() {
    final NameID nameID = new TransientNameIDGenerator(IDP, SP).getNameID(USER, REQUESTER);
    assertThat(nameID.getFormat()).isEqualTo(NameID.TRANSIENT);
    assertThat(nameID.getNameQualifier()).isEqualTo(IDP);
    assertThat(nameID.getSPNameQualifier()).isEqualTo(SP);
    assertThat(nameID.getValue()).isNotEmpty().doesNotContain(IDENTITY_NUMBER);
  }

  @Test
  void withoutASpNameQualifierNoneIsAssigned() {
    assertThat(new TransientNameIDGenerator(IDP).getNameID(USER, REQUESTER).getSPNameQualifier()).isNull();
  }

  @Test
  void aNewValueIsProducedEveryTime() {
    final TransientNameIDGenerator generator = new TransientNameIDGenerator(IDP, SP);
    assertThat(generator.getSubjectIdentifier(USER, REQUESTER))
        .isNotEqualTo(generator.getSubjectIdentifier(USER, REQUESTER));
  }

  @Test
  void theSecretDoesNotMatter() {
    final TransientNameIDGenerator generator = new TransientNameIDGenerator(IDP, SP);
    generator.setSecret(NameIDTestSupport.SECRET);
    assertThat(generator.getSubjectIdentifier(USER, REQUESTER)).isNotEmpty();
  }

  @Test
  void theGeneratorSurvivesSerialization() throws Exception {
    final TransientNameIDGenerator restored = NameIDTestSupport.roundTrip(new TransientNameIDGenerator(IDP, SP));
    final NameID nameID = restored.getNameID(USER, REQUESTER);
    assertThat(nameID.getFormat()).isEqualTo(NameID.TRANSIENT);
    assertThat(nameID.getSPNameQualifier()).isEqualTo(SP);
  }

}
