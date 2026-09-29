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
package se.swedenconnect.spring.authnserver.oidc.attributes;

import static org.assertj.core.api.Assertions.assertThat;

import java.io.Serializable;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.nimbusds.openid.connect.sdk.claims.PersonClaims;

import se.oidc.nimbus.claims.ClaimConstants;
import se.swedenconnect.spring.authnserver.attributes.AttributeIdentifiers;
import se.swedenconnect.spring.authnserver.attributes.GenericAttribute;
import se.swedenconnect.spring.authnserver.attributes.GenericRequestedAttribute;
import se.swedenconnect.spring.authnserver.attributes.release.AttributeProducer;
import se.swedenconnect.spring.authnserver.attributes.release.DefaultAttributeProducer;
import se.swedenconnect.spring.authnserver.attributes.release.DefaultAttributeReleaseManager;
import se.swedenconnect.spring.authnserver.authentication.AuthenticatedUser;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationProtocol;
import se.swedenconnect.spring.authnserver.authentication.AuthenticationRequirements;
import se.swedenconnect.spring.authnserver.authentication.UserAuthentication;

/**
 * Tests that the attributes an {@link AttributeProducer} releases map to the expected OpenID Connect claims.
 *
 * @author Martin Lindström
 */
class ReleasedAttributesToClaimsTest {

  @Test
  void theReleasedAttributesMapToClaims() {
    final AuthenticatedUser user = new AuthenticatedUser(
        List.of(
            GenericAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, "197705232382"),
            GenericAttribute.of(AttributeIdentifiers.GIVEN_NAME, "Agda"),
            GenericAttribute.of(AttributeIdentifiers.SURNAME, "Andersson"),
            GenericAttribute.of(AttributeIdentifiers.EMAIL, "agda@example.com")),
        AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, "http://id.elegnamnden.se/loa/1.0/loa3", Instant.now(),
        "192.168.1.14");

    final AuthenticationRequirements requirements = new AuthenticationRequirements();
    requirements.setRequestedAttributes(List.of(
        GenericRequestedAttribute.of(AttributeIdentifiers.PERSONAL_IDENTITY_NUMBER, true),
        GenericRequestedAttribute.of(AttributeIdentifiers.GIVEN_NAME),
        GenericRequestedAttribute.of(AttributeIdentifiers.SURNAME)));

    final UserAuthentication authentication = new UserAuthentication(user);
    authentication.registerUse(AuthenticationProtocol.OIDC, "client-1", null, List.of());
    authentication.setAuthnRequirements(requirements);

    final List<GenericAttribute<? extends Serializable>> released =
        new DefaultAttributeReleaseManager(List.of(new DefaultAttributeProducer()), null)
            .releaseAttributes(authentication);

    final List<UserClaim> claims = new OidcAttributeMapping()
        .toClaims(released, requirements.getRequestedAttributes());

    assertThat(claims).extracting(UserClaim::name).containsExactlyInAnyOrder(
        ClaimConstants.PERSONAL_IDENTITY_NUMBER_CLAIM_NAME,
        PersonClaims.GIVEN_NAME_CLAIM_NAME,
        PersonClaims.FAMILY_NAME_CLAIM_NAME);
  }

}
