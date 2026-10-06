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
package se.swedenconnect.spring.authnserver.service.authn;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;

import org.junit.jupiter.api.Test;

import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.message.GenericSignMessage;
import se.swedenconnect.spring.authnserver.message.LocalizedMessage;
import se.swedenconnect.spring.authnserver.message.MessageMimeType;
import se.swedenconnect.spring.authnserver.oidc.authentication.OidcAuthenticationRequirements;
import se.swedenconnect.spring.authnserver.saml.authentication.SamlAuthenticationRequirements;

/**
 * Tests for the helpers of {@link SimulatedAuthenticationController}. The pages themselves are tested end to end.
 *
 * @author Martin Lindström
 */
class SimulatedAuthenticationControllerTest {

  @Test
  void aSamlSignatureServiceIsRecognizedByItsEntityCategory() {
    final SamlAuthenticationRequirements requirements = new SamlAuthenticationRequirements();
    assertThat(SimulatedAuthenticationController.isSignatureService(requirements)).isFalse();
    requirements.setEntityCategories(List.of("http://id.elegnamnden.se/st/1.0/sigservice"));
    assertThat(SimulatedAuthenticationController.isSignatureService(requirements)).isTrue();
  }

  @Test
  void anOidcSignatureRequestIsRecognizedByItsScope() {
    final OidcAuthenticationRequirements requirements = new OidcAuthenticationRequirements();
    requirements.setScopes(List.of("openid"));
    assertThat(SimulatedAuthenticationController.isSignatureService(requirements)).isFalse();
    requirements.setScopes(List.of("openid", "https://id.oidc.se/scope/sign"));
    assertThat(SimulatedAuthenticationController.isSignatureService(requirements)).isTrue();
    requirements.setScopes(List.of("openid", "https://id.oidc.se/scope/signApproval"));
    assertThat(SimulatedAuthenticationController.isSignatureService(requirements)).isTrue();
  }

  @Test
  void aRequestWithASignMessageIsFromASignatureService() {
    final AuthenticationRequirements requirements = new AuthenticationRequirements();
    assertThat(SimulatedAuthenticationController.isSignatureService(requirements)).isFalse();
    requirements.setSignMessage(GenericSignMessage.ofText("en", "Sign"));
    assertThat(SimulatedAuthenticationController.isSignatureService(requirements)).isTrue();
  }

  @Test
  void theRequestedPersonalIdentityNumberIsFound() {
    final AuthenticationRequirements requirements = new AuthenticationRequirements();
    assertThat(SimulatedAuthenticationController.getRequestedPersonalIdentityNumber(requirements)).isNull();

    requirements.setRequestedAttributes(List.of(
        GenericRequestedAttribute.of(AttributeIdentifiers.GIVEN_NAME),
        GenericRequestedAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, true)));
    assertThat(SimulatedAuthenticationController.getRequestedPersonalIdentityNumber(requirements)).isNull();

    requirements.setRequestedAttributes(List.of(new GenericRequestedAttribute(
        AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, false, List.of("197705232382"), null)));
    assertThat(SimulatedAuthenticationController.getRequestedPersonalIdentityNumber(requirements))
        .isEqualTo("197705232382");

    requirements.setRequestedAttributes(List.of(new GenericRequestedAttribute(
        AttributeIdentifiers.COORDINATION_NUMBER, false, List.of("197010632391"), null)));
    assertThat(SimulatedAuthenticationController.getRequestedPersonalIdentityNumber(requirements))
        .isEqualTo("197010632391");
  }

  @Test
  void theMessageForTheLanguageIsSelectedAndOtherwiseTheFirst() {
    final GenericSignMessage message = new GenericSignMessage(List.of(
        LocalizedMessage.ofText("sv", "Svenska"), LocalizedMessage.ofText("en", "English")),
        MessageMimeType.TEXT_PLAIN, true, null);
    assertThat(SimulatedAuthenticationController.selectMessage(message, "en").getText()).isEqualTo("English");
    assertThat(SimulatedAuthenticationController.selectMessage(message, "de").getText()).isEqualTo("Svenska");
  }

}
